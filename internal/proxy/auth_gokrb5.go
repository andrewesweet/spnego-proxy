package proxy

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"golang.org/x/term"
)

// passwordRejectWarnInterval rate-limits the warning that logins are refused
// after the KDC rejected the configured password. The rejection is terminal
// until the password file changes, so a warning per request would only add log
// noise while the condition persists.
const passwordRejectWarnInterval = 5 * time.Minute

// isPasswordRejection reports whether err is the KDC rejecting the configured
// password, as opposed to a transient failure such as an unreachable KDC.
func isPasswordRejection(err error) bool {
	return err != nil && strings.Contains(err.Error(), "KDC_ERR_PREAUTH_FAILED")
}

// Gokrb5TokenProvider uses the pure-Go gokrb5 library for SPNEGO token acquisition.
// This is the fallback path used on non-macOS platforms or when -user is specified.
//
// The provider builds password and ticket-cache clients for each token
// acquisition and destroys both before returning. Go does not provide primitives
// to scrub string-backed memory, so the library's password string cannot be
// reliably zeroed and may remain in memory after the call. Use a keytab where
// this is a concern.
type Gokrb5TokenProvider struct {
	// Construction inputs, kept so the client can be rebuilt per acquisition.
	user         string
	realm        string
	cfg          *config.Config
	spn          string
	passwordFile string
	settings     []func(*client.Settings)

	mu sync.Mutex
	// stdinPassword holds the password when it was typed at a terminal
	// (-password-file omitted): there is no file to re-read, so the provider
	// keeps it for the lifetime of the process.
	stdinPassword []byte
	closed        bool

	// passwordRejected records that the KDC rejected the configured password.
	// rejectedFingerprint is a keyed HMAC of the rejected password. A random
	// per-provider key prevents offline guessing from the fingerprint alone;
	// this is a transient change detector, not a stored password verifier.
	passwordRejected    bool
	fingerprintKey      [sha256.Size]byte
	rejectedFingerprint [sha256.Size]byte
	rejectWarnTicker    *time.Ticker
	rejectWarnStop      chan struct{}
}

func getPassword(passwordFile string) ([]byte, error) {
	if passwordFile == "" {
		stdin := int(os.Stdin.Fd())
		if !term.IsTerminal(stdin) {
			return nil, errors.New("no password file specified and stdin is not a terminal")
		}
		fmt.Fprint(os.Stderr, "Password: ")
		password, err := term.ReadPassword(stdin)
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Fprintln(os.Stderr)
		return password, nil
	}

	f, err := os.Open(passwordFile) //nolint:gosec // path comes from a CLI flag, not user-controlled input
	if err != nil {
		return nil, fmt.Errorf("failed to open password file: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat password file: %w", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("password file %s has insecure permissions %04o; must not be accessible by group or others (e.g. 0600)", passwordFile, mode)
	}

	const maxPasswordFileSize = 4096
	password, err := io.ReadAll(io.LimitReader(f, maxPasswordFileSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read password file: %w", err)
	}
	return bytes.TrimRight(password, "\r\n"), nil
}

// NewGokrb5TokenProvider creates a token provider using gokrb5 with password-based auth.
func NewGokrb5TokenProvider(user, realm, cfgFile, passwordFile, proxy, explicitSPN string, debug bool) (*Gokrb5TokenProvider, error) {
	if cfgFile == "" || realm == "" {
		return nil, errors.New("-config and -realm are required when using password-based authentication")
	}

	spnVal := explicitSPN
	if spnVal == "" {
		spnVal = "HTTP/" + extractHost(proxy)
		slog.Info("inferred service principal name", "spn", spnVal)
		slog.Info("if it's not correct use the -spn flag")
	} else {
		spnVal = normalizeSPN(spnVal, '/', '@')
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load kerberos config: %w", err)
	}

	// Read the password once at start-up so a missing file, insecure
	// permissions, or a non-terminal stdin fail here rather than on the first
	// request. The file is re-read for every acquisition.
	passwd, err := getPassword(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get password: %w", err)
	}

	settings := []func(*client.Settings){
		client.DisablePAFXFAST(true),
	}
	if debug {
		settings = append(settings, client.Logger(slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)))
	}

	p := &Gokrb5TokenProvider{
		user:         user,
		realm:        realm,
		cfg:          cfg,
		spn:          spnVal,
		passwordFile: passwordFile,
		settings:     settings,
	}
	rand.Read(p.fingerprintKey[:])
	if passwordFile == "" {
		// Nothing to re-read: keep the typed password for the per-call client.
		p.stdinPassword = passwd
	} else {
		// The file is re-read for each acquisition, so the start-up copy is no
		// longer needed. Zeroing it narrows the window in which plaintext
		// credentials exist in process memory (CWE-316).
		clear(passwd)
	}
	return p, nil
}

// readPassword returns the Kerberos password for one acquisition: the current
// content of -password-file, or the password typed at start-up when no file
// was given. The caller owns the returned bytes and must zero them.
func (p *Gokrb5TokenProvider) readPassword() ([]byte, error) {
	if p.passwordFile == "" {
		return bytes.Clone(p.stdinPassword), nil
	}
	return getPassword(p.passwordFile)
}

// GetToken acquires a SPNEGO credential and initializes a security context
// via gokrb5, returning the base64-encoded SPNEGO token. It is safe for
// concurrent use.
func (p *Gokrb5TokenProvider) GetToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return "", &CredentialError{authError{msg: "token provider is closed"}}
	}
	if err := p.checkPasswordRejected(); err != nil {
		return "", err
	}

	passwd, err := p.readPassword()
	if err != nil {
		return "", &CredentialError{authError{msg: "failed to get password: check password input and file permissions"}}
	}
	fingerprint := p.passwordFingerprint(passwd)
	krbClient, err := p.acquireCredential(passwd)
	if err != nil {
		if isPasswordRejection(err) {
			p.rejectPassword(fingerprint)
		}
		return "", &CredentialError{authError{msg: fmt.Sprintf("could not acquire client credential: %v", err), cause: err}}
	}
	defer krbClient.Destroy()
	spnegoClient := spnego.SPNEGOClient(krbClient, p.spn)
	token, err := spnegoClient.InitSecContext()
	if err != nil {
		return "", &NegotiationError{authError{msg: fmt.Sprintf("could not initialize context: %v", err), cause: err}}
	}
	b, err := token.Marshal()
	if err != nil {
		return "", &NegotiationError{authError{msg: fmt.Sprintf("could not marshal SPNEGO token: %v", err), cause: err}}
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// acquireCredential uses ASExchange directly because Login starts automatic
// renewal, which can retry password logins outside the counted token path.
// The returned client has only cached tickets, so service-ticket acquisition
// cannot fall back to a password login, even if the TGT expires during the call.
func (p *Gokrb5TokenProvider) acquireCredential(passwd []byte) (*client.Client, error) {
	passwordClient := client.NewWithPassword(p.user, p.realm, string(passwd), p.cfg, p.settings...)
	clear(passwd)
	defer passwordClient.Destroy()
	req, err := messages.NewASReqForTGT(passwordClient.Credentials.Domain(), p.cfg, passwordClient.Credentials.CName())
	if err != nil {
		return nil, err
	}
	rep, err := passwordClient.ASExchange(passwordClient.Credentials.Domain(), req, 0)
	if err != nil {
		return nil, err
	}
	ticket, err := rep.Ticket.Marshal()
	if err != nil {
		return nil, err
	}
	cache := new(credentials.CCache)
	cache.DefaultPrincipal.Realm = rep.CRealm
	cache.DefaultPrincipal.PrincipalName = rep.CName
	entry := &credentials.Credential{
		Key:       rep.DecryptedEncPart.Key,
		AuthTime:  rep.DecryptedEncPart.AuthTime,
		StartTime: rep.DecryptedEncPart.StartTime,
		EndTime:   rep.DecryptedEncPart.EndTime,
		RenewTill: rep.DecryptedEncPart.RenewTill,
		Ticket:    ticket,
	}
	entry.Client = cache.DefaultPrincipal
	entry.Server.Realm = rep.Ticket.Realm
	entry.Server.PrincipalName = rep.Ticket.SName
	cache.Credentials = []*credentials.Credential{entry}
	return client.NewFromCCache(cache, p.cfg, p.settings...)
}

// passwordFingerprint detects password changes without keeping the password
// or an unkeyed digest that could be tested against a password dictionary.
func (p *Gokrb5TokenProvider) passwordFingerprint(passwd []byte) [sha256.Size]byte {
	mac := hmac.New(sha256.New, p.fingerprintKey[:])
	_, _ = mac.Write(passwd)
	return [sha256.Size]byte(mac.Sum(nil))
}

// rejectPassword records that the KDC rejected the password whose HMAC is
// fingerprint, starts periodic warnings, and stops further logins until the
// effective password changes.
func (p *Gokrb5TokenProvider) rejectPassword(fingerprint [sha256.Size]byte) {
	p.passwordRejected = true
	p.rejectedFingerprint = fingerprint
	p.warnPasswordRejected()
	if p.rejectWarnTicker != nil {
		p.rejectWarnTicker.Reset(passwordRejectWarnInterval)
		return
	}
	p.rejectWarnTicker = time.NewTicker(passwordRejectWarnInterval)
	p.rejectWarnStop = make(chan struct{})
	go p.repeatPasswordRejectionWarnings(p.rejectWarnTicker, p.rejectWarnStop)
}

// warnPasswordRejected logs that logins are refused.
func (p *Gokrb5TokenProvider) warnPasswordRejected() {
	slog.Warn("KDC rejected the configured password; refusing Kerberos logins until the password changes",
		"password_source", p.passwordSource(), "retry_after", passwordRejectWarnInterval.String())
}

func (p *Gokrb5TokenProvider) repeatPasswordRejectionWarnings(ticker *time.Ticker, stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			p.mu.Lock()
			if !p.closed && p.passwordRejected {
				_ = p.checkPasswordRejected()
				if p.passwordRejected {
					p.warnPasswordRejected()
				}
			}
			p.mu.Unlock()
		}
	}
}

// checkPasswordRejected enforces the lockout guard: once the KDC has rejected
// the configured password, no further login is sent until the password
// changes. It checks for a correction both on refused attempts and on the
// warning timer, so detection does not depend on traffic or breaker state.
func (p *Gokrb5TokenProvider) checkPasswordRejected() error {
	if !p.passwordRejected {
		return nil
	}
	passwd, err := p.readPassword()
	if err != nil {
		return &CredentialError{authError{
			msg: "KDC rejected the configured password and the password cannot be re-read to check for a correction; check password input and file permissions",
		}}
	}
	fingerprint := p.passwordFingerprint(passwd)
	clear(passwd)
	if fingerprint != p.rejectedFingerprint {
		p.passwordRejected = false
		p.rejectWarnTicker.Stop()
		slog.Info("password changed; resuming Kerberos logins", "password_source", p.passwordSource())
		return nil
	}
	return &CredentialError{authError{
		msg: fmt.Sprintf("KDC rejected the configured password; refusing Kerberos logins until the password changes (source: %s)", p.passwordSource()),
	}}
}

// passwordSource names where the password comes from, for logs and errors.
func (p *Gokrb5TokenProvider) passwordSource() string {
	if p.passwordFile == "" {
		return "terminal input at start-up"
	}
	return "password file"
}

// Close stops further token acquisition and zeroes any password typed at a
// terminal. Each acquisition destroys its own gokrb5 client, so no client
// outlives a call. It is idempotent and safe for concurrent use.
func (p *Gokrb5TokenProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	if p.rejectWarnTicker != nil {
		p.rejectWarnTicker.Stop()
		close(p.rejectWarnStop)
		p.rejectWarnTicker = nil
	}
	clear(p.stdinPassword)
	p.stdinPassword = nil
	clear(p.fingerprintKey[:])
	clear(p.rejectedFingerprint[:])
	return nil
}
