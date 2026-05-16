package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/andrewesweet/spnego-proxy/internal/proxy"
)

// cliConfig holds every CLI flag value, decoupled from flag parsing so the
// parse/validation/wiring logic can be exercised without spawning a process.
type cliConfig struct {
	Addr  string
	Proxy string
	SPN   string
	Debug bool

	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	DrainTimeout time.Duration
	KeepAlive    time.Duration
	IdleTimeout  time.Duration
	MaxConns     int
	ConnectPorts string
	AllowedIPs   string
	NoProxy      string
	CBThreshold  uint
	CBTimeout    time.Duration

	Forwarded     bool
	XForwardedFor bool

	UpstreamTLS         bool
	UpstreamCA          string
	UpstreamTLSInsecure bool

	CfgFile      string
	User         string
	Realm        string
	PasswordFile string
	ShowVersion  bool
}

// parseFlags defines the CLI flags, parses args, and returns the populated
// cliConfig together with the FlagSet (so callers can render usage). It uses
// flag.ContinueOnError so parse failures are returned rather than calling
// os.Exit; main() maps the error to the historical exit codes.
func parseFlags(args []string) (*cliConfig, *flag.FlagSet, error) {
	c := &cliConfig{}
	fs := flag.NewFlagSet("spnego-proxy", flag.ContinueOnError)

	fs.StringVar(&c.Addr, "addr", "127.0.0.1:8080", "bind address")
	fs.StringVar(&c.Proxy, "proxy", "", "proxy address")
	fs.StringVar(&c.SPN, "spn", "", "service principal name; accepts service@host or service/host (default: derived from -proxy)")
	fs.BoolVar(&c.Debug, "debug", false, "turn on debugging")

	fs.DurationVar(&c.DialTimeout, "dial-timeout", 30*time.Second, "timeout for connecting to upstream proxy")
	fs.DurationVar(&c.ReadTimeout, "read-timeout", 30*time.Second, "timeout for reading client HTTP request")
	fs.DurationVar(&c.DrainTimeout, "drain-timeout", 30*time.Second, "timeout for draining in-flight connections on shutdown")
	fs.DurationVar(&c.KeepAlive, "keepalive", 30*time.Second, "TCP keepalive period for idle connection detection (0 to disable)")
	fs.DurationVar(&c.IdleTimeout, "idle-timeout", 5*time.Minute,
		"idle timeout for CONNECT tunnels; connections with no data flow are closed after this duration (0 to disable)")
	fs.IntVar(&c.MaxConns, "max-conns", 512, "maximum number of concurrent connections (0 for unlimited)")
	fs.StringVar(&c.ConnectPorts, "connect-ports", "443", "comma-separated list of ports allowed for CONNECT tunneling (default: 443; use "+proxy.ConnectPortWildcard+" for all)")
	fs.StringVar(&c.AllowedIPs, "allowed-ips", "",
		"comma-separated list of allowed client IPs or CIDR ranges (empty = allow all; recommended when binding to non-loopback)")
	fs.StringVar(&c.NoProxy, "noproxy", "",
		"comma-separated list of hosts/domains/IPs/CIDRs to bypass upstream proxy (supports *.domain, .domain, CIDR, * for all; also reads NO_PROXY/no_proxy env vars)")
	fs.UintVar(&c.CBThreshold, "cb-threshold", uint(proxy.CbConsecutiveFailures),
		"consecutive failures before circuit breaker opens")
	fs.DurationVar(&c.CBTimeout, "cb-timeout", proxy.CbTimeout,
		"circuit breaker cooldown duration")

	fs.BoolVar(&c.Forwarded, "forwarded", false, "inject RFC 7239 Forwarded header with obfuscated client identifier")
	fs.BoolVar(&c.XForwardedFor, "x-forwarded-for", false, "inject X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host headers")

	fs.BoolVar(&c.UpstreamTLS, "upstream-tls", false,
		"use TLS for upstream proxy connection")
	fs.StringVar(&c.UpstreamCA, "upstream-ca", "",
		"path to CA certificate for upstream TLS verification")
	fs.BoolVar(&c.UpstreamTLSInsecure, "upstream-tls-insecure", false,
		"skip TLS certificate verification for upstream (not recommended)")

	// Flags for gokrb5 password-based auth (optional on macOS, required on other platforms)
	fs.StringVar(&c.CfgFile, "config", "", "kerberos config file")
	fs.StringVar(&c.User, "user", "", "kerberos user name")
	fs.StringVar(&c.Realm, "realm", "", "kerberos realm")
	fs.StringVar(&c.PasswordFile, "password-file", "", "password file path")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version information and exit")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", versionString())
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", "spnego-proxy")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return nil, fs, err
	}
	return c, fs, nil
}

// buildProvider selects and constructs the token provider from the CLI
// config: gokrb5 password-based auth when -user is set, otherwise the
// platform-native GSS-API provider. The result is wrapped in the circuit
// breaker.
func buildProvider(c *cliConfig) (proxy.TokenProvider, error) {
	var provider proxy.TokenProvider
	var err error

	if c.User != "" {
		// Explicit user provided — use gokrb5 password-based auth on any platform
		provider, err = proxy.NewGokrb5TokenProvider(c.User, c.Realm, c.CfgFile, c.PasswordFile, c.Proxy, c.SPN, c.Debug)
	} else {
		// Try platform-native GSS-API (macOS) or error on other platforms
		provider, err = proxy.NewNativeTokenProvider(c.Proxy, c.SPN)
	}
	if err != nil {
		return nil, err
	}
	return proxy.NewCircuitBreakerTokenProvider(provider, uint32(c.CBThreshold), c.CBTimeout), nil //nolint:gosec // CLI flag value; overflow not a concern
}
