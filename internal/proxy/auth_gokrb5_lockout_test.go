package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"log/slog"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/jcmturner/krb5test"
)

// testKDCUser and testKDCSPN are the principals every test KDC in this file
// knows about.
const (
	testKDCUser = "testuser"
	testKDCSPN  = "HTTP/proxy.test.realm.com"
)

// asExchangeCounter counts the AS exchanges a mock KDC serves, which is the
// observable form of "a password login happened".
type asExchangeCounter struct {
	mu sync.Mutex
	re *regexp.Regexp
	n  int
}

func (c *asExchangeCounter) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n += len(c.re.FindAll(b, -1))
	return len(b), nil
}

func (c *asExchangeCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// startLockoutKDC starts a mock KDC and returns it with the counter of the AS
// exchanges it serves. A non-zero lifetime makes the KDC issue TGTs that live
// that long and are not renewable, so gokrb5's renewal goroutine takes the
// password-login branch when it fires.
func startLockoutKDC(t *testing.T, lifetime time.Duration) (*krb5test.KDC, *asExchangeCounter) {
	t.Helper()
	as := &asExchangeCounter{re: regexp.MustCompile(`AS_REQ from=[^ ]+: selected enctype`)}
	kdc, err := krb5test.NewKDC(map[string][]string{testKDCUser: {"testgroup"}, testKDCSPN: {}}, log.New(as, "", 0))
	if err != nil {
		t.Fatalf("create mock KDC: %v", err)
	}
	if lifetime > 0 {
		kdc.KRB5Conf.LibDefaults.TicketLifetime = lifetime
		kdc.KRB5Conf.LibDefaults.RenewLifetime = 0
	}
	kdc.Start()
	t.Cleanup(kdc.Close)
	return kdc, as
}

// newLockoutProvider builds a Gokrb5TokenProvider that authenticates as
// testKDCUser against the mock KDC, reading its password from a file the
// caller can rewrite.
func newLockoutProvider(t *testing.T, kdc *krb5test.KDC, passwordFile string) *Gokrb5TokenProvider {
	t.Helper()
	cfgFile := writeMockKDCKrb5Conf(t, kdc.TCPListener.Addr().String(), kdc.Realm)
	p, err := NewGokrb5TokenProvider(testKDCUser, kdc.Realm, cfgFile, passwordFile, "proxy.test.realm.com:3128", testKDCSPN, false)
	if err != nil {
		t.Fatalf("create token provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// lockedBuffer is a goroutine-safe sink for captured slog output.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureSlog redirects the default logger into a buffer for one test.
func captureSlog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

// TestGokrb5TokenProviderLogsInOnlyInsideGetToken pins that no password login
// runs outside the counted token path. gokrb5 starts a renewal goroutine per
// TGT; past renew-till that goroutine logs in with the stored password, so a
// password change used to produce rejected logins with no GetToken call and no
// breaker failure counted.
func TestGokrb5TokenProviderLogsInOnlyInsideGetToken(t *testing.T) {
	kdc, as := startLockoutKDC(t, 3*time.Second)
	pwFile := writePasswordFile(t, kdc.Principals[testKDCUser].Password, 0o600)
	cb := NewCircuitBreakerTokenProvider(newLockoutProvider(t, kdc, pwFile), CBConsecutiveFailures, CBTimeout)
	t.Cleanup(func() { _ = cb.Close() })

	if _, err := cb.GetToken(); err != nil {
		t.Fatalf("first GetToken: %v", err)
	}
	if got := as.count(); got == 0 {
		t.Fatal("the first GetToken reached no AS exchange: the KDC counter is not observing logins")
	}

	// The account password changes at the KDC while the proxy holds the old
	// one, so any login the proxy attempts from now on is rejected.
	newPassword := "a-new-password"
	if err := kdc.Keytab.AddEntry(testKDCUser, kdc.Realm, newPassword, time.Now().UTC(), 2, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"]); err != nil {
		t.Fatalf("change password at the KDC: %v", err)
	}

	idleStart := as.count()
	// 5/6 of a 3 s TGT is 2.5 s: the renewal goroutine fires inside this wait.
	time.Sleep(3500 * time.Millisecond)
	if got := as.count() - idleStart; got != 0 {
		t.Errorf("KDC served %d AS exchanges with no GetToken call: a password login ran outside the token path", got)
	}

	// Every rejected login now happens inside GetToken, so the breaker counts
	// all of them and opens once the threshold is reached.
	for i := range int(CBConsecutiveFailures) - 1 {
		if _, err := cb.GetToken(); err == nil {
			t.Fatalf("GetToken %d: expected the KDC to reject the stale password", i+1)
		}
	}
	wantFailures := uint32(CBConsecutiveFailures) - 1
	if got := cb.cb.Counts().TotalFailures; got != wantFailures {
		t.Errorf("breaker counted %d failures over %d rejected GetToken calls, want %d", got, wantFailures, wantFailures)
	}
	if _, err := cb.GetToken(); err == nil {
		t.Fatal("expected the KDC to reject the stale password")
	}
	_, err := cb.GetToken()
	if err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
		t.Fatalf("expected the breaker to open after %d rejected logins, got: %v", CBConsecutiveFailures, err)
	}
}

func startPasswordRejectingKDC(t *testing.T, kdc *krb5test.KDC) (string, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	etypeInfo, err := asn1.Marshal(types.ETypeInfo2{{EType: etypeID.AES256_CTS_HMAC_SHA1_96}})
	if err != nil {
		t.Fatal(err)
	}
	rejection := messages.NewKRBError(kdc.SName, kdc.Realm, errorcode.KDC_ERR_PREAUTH_FAILED, "")
	rejection.EData, err = asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_ETYPE_INFO2, PADataValue: etypeInfo}})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := rejection.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	rejections := make(chan struct{}, 2)
	go func() {
		defer close(done)
		for range 2 {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Error(err)
				return
			}
			var size uint32
			if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
				t.Error(err)
				return
			}
			if _, err := io.CopyN(io.Discard, conn, int64(size)); err != nil {
				t.Error(err)
				return
			}
			rejections <- struct{}{}
			replyLen := uint64(len(reply))
			if replyLen > math.MaxUint32 {
				t.Error("KDC reply exceeds uint32 length")
				return
			}
			if err := binary.Write(conn, binary.BigEndian, uint32(replyLen)); err != nil {
				t.Error(err)
				return
			}
			if _, err := conn.Write(reply); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String(), rejections
}

// TestGokrb5TokenProviderStopsLoginsAfterPasswordRejection pins that a KDC
// password rejection is terminal until the password file changes: the proxy
// stops sending logins, warns once rather than once per request, and resumes
// on its own when the file content changes.
func TestGokrb5TokenProviderStopsLoginsAfterPasswordRejection(t *testing.T) {
	kdc, as := startLockoutKDC(t, 0)
	pwFile := writePasswordFile(t, "wrong-password", 0o600)
	p := newLockoutProvider(t, kdc, pwFile)
	logs := captureSlog(t)
	address, rejections := startPasswordRejectingKDC(t, kdc)
	p.cfg.Realms[0].KDC = []string{address}

	if _, err := p.GetToken(); err == nil || !strings.Contains(err.Error(), "KDC_ERR_PREAUTH_FAILED") {
		t.Fatalf("expected KDC pre-authentication rejection, got %v", err)
	}
	if got := len(rejections); got != 2 {
		t.Fatalf("KDC received %d AS requests, want 2 (initial request and pre-authentication retry)", got)
	}
	p.cfg.Realms[0].KDC = []string{kdc.TCPListener.Addr().String()}
	if err := os.WriteFile(pwFile, []byte("wrong-password\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	const refusedCalls = 3
	for i := range refusedCalls {
		_, err := p.GetToken()
		if err == nil {
			t.Fatalf("call %d after the rejection: expected the provider to refuse the login", i+2)
		}
		if !strings.Contains(err.Error(), "password") {
			t.Errorf("call %d: refusal does not explain that the password was rejected: %v", i+2, err)
		}
	}
	if got := as.count(); got != 0 {
		t.Errorf("KDC served %d AS exchanges after rejection and a CR/LF-only change, want 0", got)
	}
	if got := strings.Count(logs.String(), "refusing Kerberos logins"); got != 1 {
		t.Errorf("warning logged %d times across %d refused calls, want 1 (rate-limited, not per request)", got, refusedCalls+1)
	}

	// The operator writes the correct password into the file: logins resume
	// without a restart.
	if err := os.WriteFile(pwFile, []byte(kdc.Principals[testKDCUser].Password), 0o600); err != nil {
		t.Fatalf("rewrite password file: %v", err)
	}
	if _, err := p.GetToken(); err != nil {
		t.Fatalf("GetToken after the password file changed: %v", err)
	}
	if got := as.count(); got != 1 {
		t.Errorf("KDC served %d AS exchanges after the password changed, want 1", got)
	}
}

func startDelayedKDC(t *testing.T, upstream string, phase int) (string, <-chan struct{}, chan<- struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	paused := make(chan struct{})
	release := make(chan struct{})
	var delayed atomic.Bool
	readPacket := func(r io.Reader) ([]byte, error) {
		var header [4]byte
		if _, err := io.ReadFull(r, header[:]); err != nil {
			return nil, err
		}
		packet := make([]byte, 4+int(binary.BigEndian.Uint32(header[:])))
		copy(packet, header[:])
		_, err := io.ReadFull(r, packet[4:])
		return packet, err
	}
	relay := func(conn net.Conn) error {
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		request, err := readPacket(conn)
		if err != nil {
			return err
		}
		server, err := net.DialTimeout("tcp", upstream, 5*time.Second)
		if err != nil {
			return err
		}
		defer func() { _ = server.Close() }()
		if err := server.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		if _, err := server.Write(request); err != nil {
			return err
		}
		reply, err := readPacket(server)
		if err != nil {
			return err
		}
		var envelope asn1.RawValue
		if _, err := asn1.Unmarshal(request[4:], &envelope); err != nil {
			return err
		}
		if envelope.Tag == phase && delayed.CompareAndSwap(false, true) {
			close(paused)
			<-release
		}
		_, err = conn.Write(reply)
		return err
	}
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			handlers.Go(func() {
				if err := relay(conn); err != nil {
					t.Errorf("relay KDC exchange: %v", err)
				}
			})
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-release:
		default:
			close(release)
		}
		<-done
		handlers.Wait()
	})
	return ln.Addr().String(), paused, release
}

func TestGokrb5TokenProviderDoesNotReloginDuringAcquisition(t *testing.T) {
	for _, phase := range []int{msgtype.KRB_AS_REQ, msgtype.KRB_TGS_REQ} {
		t.Run(map[int]string{msgtype.KRB_AS_REQ: "delayed TGT", msgtype.KRB_TGS_REQ: "delayed service ticket"}[phase], func(t *testing.T) {
			kdc, as := startLockoutKDC(t, 3*time.Second)
			pwFile := writePasswordFile(t, kdc.Principals[testKDCUser].Password, 0o600)
			p := newLockoutProvider(t, kdc, pwFile)
			cb := NewCircuitBreakerTokenProvider(p, CBConsecutiveFailures, CBTimeout)
			t.Cleanup(func() { _ = cb.Close() })
			address, paused, release := startDelayedKDC(t, kdc.TCPListener.Addr().String(), phase)
			p.cfg.Realms[0].KDC = []string{address}
			result := make(chan error, 1)
			go func() {
				token, err := cb.GetToken()
				if err == nil && token == "" {
					err = errors.New("empty SPNEGO token")
				}
				result <- err
			}()
			select {
			case <-paused:
			case <-time.After(5 * time.Second):
				t.Fatal("KDC did not reach the delayed exchange")
			}
			if err := kdc.Keytab.AddEntry(testKDCUser, kdc.Realm, "changed-at-kdc", time.Now().UTC(), 2, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
				t.Fatal(err)
			}
			time.Sleep(3500 * time.Millisecond)
			if got := as.count(); got != 1 {
				t.Errorf("KDC served %d AS exchanges during one pending GetToken, want 1", got)
			}
			close(release)
			select {
			case err := <-result:
				if phase == msgtype.KRB_TGS_REQ && err != nil {
					t.Fatalf("delayed service-ticket acquisition failed: %v", err)
				}
				if phase == msgtype.KRB_AS_REQ && err == nil {
					t.Fatal("expected the expired TGT to fail without a password refresh")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("GetToken did not complete after releasing the KDC")
			}
			if got := as.count(); got != 1 {
				t.Errorf("KDC served %d AS exchanges including foreground refresh, want 1", got)
			}
			counts := cb.cb.Counts()
			if phase == msgtype.KRB_TGS_REQ && counts.TotalSuccesses != 1 {
				t.Errorf("breaker successes = %d, want 1", counts.TotalSuccesses)
			}
			if phase == msgtype.KRB_AS_REQ && counts.TotalFailures != 1 {
				t.Errorf("breaker failures = %d, want 1", counts.TotalFailures)
			}
		})
	}
}

func TestGokrb5TokenProviderPeriodicRejectionWarnings(t *testing.T) {
	for _, finish := range []string{"password change", "close"} {
		t.Run(finish, func(t *testing.T) {
			kdc, as := startLockoutKDC(t, 0)
			pwFile := writePasswordFile(t, "wrong-password", 0o600)
			p := newLockoutProvider(t, kdc, pwFile)
			address, rejections := startPasswordRejectingKDC(t, kdc)
			p.cfg.Realms[0].KDC = []string{address}
			logs := captureSlog(t)
			synctest.Test(t, func(t *testing.T) {
				defer func() { _ = p.Close() }()
				cb := NewCircuitBreakerTokenProvider(p, 1, time.Hour)
				if _, err := cb.GetToken(); err == nil || !strings.Contains(err.Error(), "KDC_ERR_PREAUTH_FAILED") {
					t.Fatalf("expected KDC rejection, got %v", err)
				}
				if _, err := cb.GetToken(); err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
					t.Fatalf("expected an open circuit breaker, got %v", err)
				}
				for want := 2; want <= 3; want++ {
					time.Sleep(5 * time.Minute)
					synctest.Wait()
					if got := strings.Count(logs.String(), "refusing Kerberos logins"); got != want {
						t.Fatalf("warnings without traffic = %d, want %d", got, want)
					}
				}
				if got := len(rejections); got != 2 {
					t.Errorf("KDC received %d AS requests, want only the initial pair", got)
				}
				if finish == "close" {
					if err := p.Close(); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(pwFile, []byte(kdc.Principals[testKDCUser].Password), 0o600); err != nil {
						t.Fatal(err)
					}
					time.Sleep(5 * time.Minute)
					synctest.Wait()
					if !strings.Contains(logs.String(), "password changed; resuming Kerberos logins") {
						t.Fatal("timer did not detect the corrected password")
					}
				}
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				if got := strings.Count(logs.String(), "refusing Kerberos logins"); got != 3 {
					t.Errorf("warnings after %s = %d, want 3", finish, got)
				}
				if got := as.count(); got != 0 {
					t.Errorf("warning timer sent %d AS exchanges, want 0", got)
				}
			})
		})
	}
}

func TestGokrb5TokenProviderRejectionTicksAfterDelayedDelivery(t *testing.T) {
	for _, action := range []string{"repeat warning", "password change"} {
		t.Run(action, func(t *testing.T) {
			logs := captureSlog(t)
			synctest.Test(t, func(t *testing.T) {
				pwFile := writePasswordFile(t, "rejected-password", 0o600)
				p := &Gokrb5TokenProvider{
					passwordFile:        pwFile,
					passwordRejected:    true,
					rejectedFingerprint: sha256.Sum256([]byte("rejected-password")),
					rejectWarnTicker:    time.NewTicker(5 * time.Minute),
					rejectWarnStop:      make(chan struct{}),
				}
				defer func() { _ = p.Close() }()
				time.Sleep(5*time.Minute + 10*time.Millisecond)
				go p.repeatPasswordRejectionWarnings(p.rejectWarnTicker, p.rejectWarnStop)
				synctest.Wait()
				if got := strings.Count(logs.String(), "refusing Kerberos logins"); got != 1 {
					t.Fatalf("warnings after delayed first tick = %d, want 1", got)
				}
				if action == "password change" {
					if err := os.WriteFile(pwFile, []byte("corrected-password"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				time.Sleep(5*time.Minute - 9*time.Millisecond)
				synctest.Wait()
				if action == "repeat warning" {
					if got := strings.Count(logs.String(), "refusing Kerberos logins"); got != 2 {
						t.Errorf("warnings at the second scheduled tick = %d, want 2", got)
					}
				} else {
					if !strings.Contains(logs.String(), "password changed; resuming Kerberos logins") {
						t.Error("second scheduled tick did not detect the corrected password")
					}
					time.Sleep(10 * time.Minute)
					synctest.Wait()
					if got := strings.Count(logs.String(), "refusing Kerberos logins"); got != 1 {
						t.Errorf("warnings after correction = %d, want 1", got)
					}
				}
			})
		})
	}
}

func TestGokrb5TokenProviderRecoversAfterClockSkew(t *testing.T) {
	kdc, as := startLockoutKDC(t, 0)
	pwFile := writePasswordFile(t, kdc.Principals[testKDCUser].Password, 0o600)
	p := newLockoutProvider(t, kdc, pwFile)
	clockSkew := p.cfg.LibDefaults.Clockskew
	p.cfg.LibDefaults.Clockskew = -time.Second
	if _, err := p.GetToken(); err == nil || !strings.Contains(err.Error(), "clock skew with KDC too large") {
		t.Fatalf("expected clock-skew verification failure, got %v", err)
	}
	p.cfg.LibDefaults.Clockskew = clockSkew
	if token, err := p.GetToken(); err != nil || token == "" {
		t.Fatalf("GetToken after clock-skew correction: token=%q, error=%v", token, err)
	}
	if got := as.count(); got != 2 {
		t.Errorf("KDC served %d AS exchanges, want 2 with the unchanged password", got)
	}
}

// TestIsPasswordRejection pins which failures the provider treats as a KDC
// password rejection. A transient failure must not stop logins, because that
// would leave the proxy unable to recover from a KDC restart.
func TestIsPasswordRejection(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "pre-authentication failed",
			err:  errors.New("[Root cause: KDC_Error] AS Exchange Error: kerberos error response from KDC: KRB Error: KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid"),
			want: true,
		},
		{
			name: "generic AS-REP verification wrapper",
			err:  errors.New("could not acquire client credential: AS Exchange Error: AS_REP is not valid or client password/keytab incorrect"),
			want: false,
		},
		{
			name: "clock skew in AS-REP verification wrapper",
			err:  errors.New("AS Exchange Error: AS_REP is not valid or client password/keytab incorrect: clock skew with KDC too large"),
			want: false,
		},
		{
			name: "KDC unreachable",
			err:  errors.New("dial tcp 127.0.0.1:88: connect: connection refused"),
			want: false,
		},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPasswordRejection(tt.err); got != tt.want {
				t.Errorf("isPasswordRejection(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestGokrb5TokenProviderBurstStopsAtThreshold pins the reported surface: a
// burst of client connections whose token acquisition fails must not send one
// rejected login per connection to the KDC, whatever the number of connections.
func TestGokrb5TokenProviderBurstStopsAtThreshold(t *testing.T) {
	kdc, as := startLockoutKDC(t, 0)
	pwFile := writePasswordFile(t, "wrong-password", 0o600)
	cb := NewCircuitBreakerTokenProvider(newLockoutProvider(t, kdc, pwFile), CBConsecutiveFailures, CBTimeout)
	t.Cleanup(func() { _ = cb.Close() })

	const clients = 10
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	cfg := defaultTestConfig("127.0.0.1:1", cb)
	accepted := make(chan net.Conn, clients)
	go func() {
		for range clients {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()

	var handlers sync.WaitGroup
	go func() {
		for range clients {
			select {
			case conn := <-accepted:
				handlers.Go(func() { handleClient(conn, cfg) })
			case <-time.After(10 * time.Second):
				return
			}
		}
	}()

	statuses := make(chan string, clients)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range clients {
		wg.Go(func() {
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				statuses <- "dial error: " + err.Error()
				return
			}
			defer func() { _ = conn.Close() }()
			<-start
			_, _ = io.WriteString(conn, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n")
			response, _ := io.ReadAll(conn)
			line, _, _ := bytes.Cut(response, []byte("\r\n"))
			statuses <- string(line)
		})
	}
	close(start)
	wg.Wait()
	handlers.Wait()
	close(statuses)

	if got := as.count(); got > int(CBConsecutiveFailures) {
		t.Errorf("KDC served %d AS exchanges for %d concurrent clients, want at most %d (the breaker threshold)", got, clients, CBConsecutiveFailures)
	}
	responses := make([]string, 0, clients)
	for status := range statuses {
		responses = append(responses, status)
	}
	if len(responses) != clients {
		t.Fatalf("collected %d client responses, want %d", len(responses), clients)
	}
	for _, status := range responses {
		if !strings.Contains(status, "502") {
			t.Errorf("client received %q, want a 502 error response", status)
		}
	}
}
