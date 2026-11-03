package proxy

import (
	"bytes"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
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

// TestGokrb5TokenProviderStopsLoginsAfterPasswordRejection pins that a KDC
// password rejection is terminal until the password file changes: the proxy
// stops sending logins, warns once rather than once per request, and resumes
// on its own when the file content changes.
func TestGokrb5TokenProviderStopsLoginsAfterPasswordRejection(t *testing.T) {
	kdc, as := startLockoutKDC(t, 0)
	pwFile := writePasswordFile(t, "wrong-password", 0o600)
	p := newLockoutProvider(t, kdc, pwFile)
	logs := captureSlog(t)

	if _, err := p.GetToken(); err == nil {
		t.Fatal("expected the KDC to reject the wrong password")
	}
	if got := as.count(); got != 1 {
		t.Fatalf("KDC served %d AS exchanges for the first rejected login, want 1", got)
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
	if got := as.count(); got != 1 {
		t.Errorf("KDC served %d AS exchanges after the password was rejected, want 1: logins continued after the rejection", got)
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
	if got := as.count(); got != 2 {
		t.Errorf("KDC served %d AS exchanges in total, want 2 (the rejected login and the one after the file changed)", got)
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
			name: "AS-REP not decryptable with the configured password",
			err:  errors.New("could not acquire client credential: AS Exchange Error: AS_REP is not valid or client password/keytab incorrect"),
			want: true,
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
	for status := range statuses {
		if !strings.Contains(status, "502") {
			t.Errorf("client received %q, want a 502 error response", status)
		}
	}
}
