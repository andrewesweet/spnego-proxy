package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

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
}

func getPassword(passwordFile string) (string, error) {
	if passwordFile == "" {
		stdin := int(os.Stdin.Fd())
		if !term.IsTerminal(stdin) {
			return "", errors.New("no password file specified and stdin is not a terminal")
		}
		stdout := int(os.Stdout.Fd())
		if !term.IsTerminal(stdout) {
			return "", errors.New("no password file specified and stdout is not a terminal")
		}
		fmt.Print("Password: ")
		password, err := term.ReadPassword(stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
		return string(password), nil
	}

	f, err := os.Open(passwordFile) //nolint:gosec // path comes from a CLI flag, not user-controlled input
	if err != nil {
		return "", fmt.Errorf("failed to open password file: %w", err)
	}
	defer func() { _ = f.Close() }()
	password, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("failed to read password file: %w", err)
	}
	return strings.TrimRight(string(password), "\r\n"), nil
}

// NewGokrb5TokenProvider creates a token provider using gokrb5 with password-based auth.
func NewGokrb5TokenProvider(user, realm, cfgFile, passwordFile, proxy, explicitSPN string, debug bool) (*Gokrb5TokenProvider, error) {
	if cfgFile == "" || realm == "" {
		return nil, errors.New("-config and -realm are required when using password-based authentication")
	}

	spnVal := explicitSPN
	if spnVal == "" {
		host, _, err := net.SplitHostPort(proxy)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy address: %w", err)
		}
		spnVal = "HTTP/" + host
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
	cli := client.NewWithPassword(user, realm, passwd, cfg, opts...)

	return &Gokrb5TokenProvider{
		spnegoClient: spnego.SPNEGOClient(cli, spnVal),
	}, nil
}

func (p *Gokrb5TokenProvider) GetToken(_ string) (string, error) {
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
	return nil
}
