package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"unsafe"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"golang.org/x/term"
)

// Gokrb5TokenProvider uses the pure-Go gokrb5 library for SPNEGO token acquisition.
// This is the fallback path used on non-macOS platforms or when -user is specified.
type Gokrb5TokenProvider struct {
	spnegoClient *spnego.SPNEGO
	mu           sync.Mutex
	passwd       []byte // retained so Close can zero the backing memory
}

// zeroBytes overwrites a byte slice with zeros to minimize how long
// sensitive material (passwords) remains in memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
		logger.Println("inferred service principal name:", spnVal)
		logger.Println("if it's not correct use the -spn flag")
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
		opts = append(opts, client.Logger(logger))
	}
	// Use unsafe.String so the string shares the passwd byte slice's backing
	// memory instead of creating a separate heap copy that cannot be zeroed.
	// The byte slice is retained in the struct and zeroed in Close().
	passwdStr := unsafe.String(unsafe.SliceData(passwd), len(passwd))
	cli := client.NewWithPassword(user, realm, passwdStr, cfg, opts...)

	return &Gokrb5TokenProvider{
		spnegoClient: spnego.SPNEGOClient(cli, spnVal),
		passwd:       passwd,
	}, nil
}

func (p *Gokrb5TokenProvider) GetToken() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.spnegoClient.AcquireCred(); err != nil {
		return "", fmt.Errorf("could not acquire client credential: %w", err)
	}
	token, err := p.spnegoClient.InitSecContext()
	if err != nil {
		return "", fmt.Errorf("could not initialize context: %w", err)
	}
	b, err := token.Marshal()
	if err != nil {
		return "", fmt.Errorf("could not marshal SPNEGO token: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (p *Gokrb5TokenProvider) Close() error {
	zeroBytes(p.passwd)
	return nil
}
