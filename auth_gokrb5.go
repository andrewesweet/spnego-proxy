package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"golang.org/x/term"
)

// Gokrb5TokenProvider uses the pure-Go gokrb5 library for SPNEGO token acquisition.
// This is the fallback path used on non-macOS platforms or when -user is specified.
//
// Note: the gokrb5 client retains the password string in memory for the
// lifetime of the process so it can re-authenticate when the TGT expires.
// Go does not provide primitives to scrub string-backed memory, so the
// password cannot be reliably zeroed. Use a keytab instead of a password
// in environments where this is a concern.
type Gokrb5TokenProvider struct {
	krbClient    *client.Client
	spnegoClient *spnego.SPNEGO
	mu           sync.Mutex
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

	passwd, err := getPassword(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get password: %w", err)
	}

	opts := []func(*client.Settings){
		client.DisablePAFXFAST(true),
	}
	if debug {
		opts = append(opts, client.Logger(slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)))
	}
	cli := client.NewWithPassword(user, realm, string(passwd), cfg, opts...)

	return &Gokrb5TokenProvider{
		krbClient:    cli,
		spnegoClient: spnego.SPNEGOClient(cli, spnVal),
	}, nil
}

func (p *Gokrb5TokenProvider) GetToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.spnegoClient.AcquireCred(); err != nil {
		return "", &CredentialError{authError{msg: fmt.Sprintf("could not acquire client credential: %v", err), cause: err}}
	}
	token, err := p.spnegoClient.InitSecContext()
	if err != nil {
		return "", &NegotiationError{authError{msg: fmt.Sprintf("could not initialize context: %v", err), cause: err}}
	}
	b, err := token.Marshal()
	if err != nil {
		return "", &NegotiationError{authError{msg: fmt.Sprintf("could not marshal SPNEGO token: %v", err), cause: err}}
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (p *Gokrb5TokenProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.krbClient != nil {
		p.krbClient.Destroy()
		p.krbClient = nil
	}
	return nil
}
