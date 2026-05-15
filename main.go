// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
)

func init() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "bind address")
	proxy := flag.String("proxy", "", "proxy address")
	spn := flag.String("spn", "", "service principal name; accepts service@host or service/host (default: derived from -proxy)")
	debug := flag.Bool("debug", false, "turn on debugging")

	dialTimeout := flag.Duration("dial-timeout", 30*time.Second, "timeout for connecting to upstream proxy")
	readTimeout := flag.Duration("read-timeout", 30*time.Second, "timeout for reading client HTTP request")
	drainTimeout := flag.Duration("drain-timeout", 30*time.Second, "timeout for draining in-flight connections on shutdown")
	keepAlive := flag.Duration("keepalive", 30*time.Second, "TCP keepalive period for idle connection detection (0 to disable)")
	idleTimeout := flag.Duration("idle-timeout", 5*time.Minute,
		"idle timeout for CONNECT tunnels; connections with no data flow are closed after this duration (0 to disable)")
	maxConns := flag.Int("max-conns", 512, "maximum number of concurrent connections (0 for unlimited)")
	connectPortsFlag := flag.String("connect-ports", "443", "comma-separated list of ports allowed for CONNECT tunneling (default: 443; use "+connectPortWildcard+" for all)")
	allowedIPs := flag.String("allowed-ips", "",
		"comma-separated list of allowed client IPs or CIDR ranges (empty = allow all; recommended when binding to non-loopback)")
	noProxyFlag := flag.String("noproxy", "",
		"comma-separated list of hosts/domains/IPs/CIDRs to bypass upstream proxy (supports *.domain, .domain, CIDR, * for all; also reads NO_PROXY/no_proxy env vars)")
	cbThreshold := flag.Uint("cb-threshold", uint(cbConsecutiveFailures),
		"consecutive failures before circuit breaker opens")
	cbTimeoutFlag := flag.Duration("cb-timeout", cbTimeout,
		"circuit breaker cooldown duration")

	forwardedFlag := flag.Bool("forwarded", false, "inject RFC 7239 Forwarded header with obfuscated client identifier")
	xForwardedForFlag := flag.Bool("x-forwarded-for", false, "inject X-Forwarded-For, X-Forwarded-Proto, and X-Forwarded-Host headers")

	upstreamTLS := flag.Bool("upstream-tls", false,
		"use TLS for upstream proxy connection")
	upstreamCA := flag.String("upstream-ca", "",
		"path to CA certificate for upstream TLS verification")
	upstreamTLSInsecure := flag.Bool("upstream-tls-insecure", false,
		"skip TLS certificate verification for upstream (not recommended)")

	// Flags for gokrb5 password-based auth (optional on macOS, required on other platforms)
	cfgFile := flag.String("config", "", "kerberos config file")
	user := flag.String("user", "", "kerberos user name")
	realm := flag.String("realm", "", "kerberos realm")
	passwordFile := flag.String("password-file", "", "password file path")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", versionString())
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", "spnego-proxy")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

	if *debug {
		logLevel.Set(slog.LevelDebug)
	}

	if *addr == "" || *proxy == "" {
		slog.Error("-addr and -proxy are required")
		flag.Usage()
		os.Exit(1)
	}

	var provider TokenProvider
	var err error

	if *user != "" {
		// Explicit user provided — use gokrb5 password-based auth on any platform
		provider, err = NewGokrb5TokenProvider(*user, *realm, *cfgFile, *passwordFile, *proxy, *spn, *debug)
	} else {
		// Try platform-native GSS-API (macOS) or error on other platforms
		provider, err = newNativeTokenProvider(*proxy, *spn)
	}
	if err != nil {
		// codeql[go/clear-text-logging]
		slog.Error("failed to create token provider", "error", err)
		os.Exit(1)
	}
	provider = NewCircuitBreakerTokenProvider(provider, uint32(*cbThreshold), *cbTimeoutFlag) //nolint:gosec // CLI flag value; overflow not a concern

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to listen", "error", err, "addr", *addr)
		os.Exit(1)
	}
	pseudonym := generateViaPseudonym()

	connectPorts := splitCSV(*connectPortsFlag)

	allowList, err := parseAllowList(*allowedIPs)
	if err != nil {
		slog.Error("invalid -allowed-ips", "error", err)
		os.Exit(1)
	}

	noProxyPatterns := resolveNoProxy(*noProxyFlag)
	var noProxy *NoProxyMatcher
	if noProxyPatterns != "" {
		noProxy = NewNoProxyMatcher(noProxyPatterns)
		source := "flag"
		if *noProxyFlag == "" {
			source = "env"
		}
		slog.Info("noproxy bypass configured", "patterns", noProxyPatterns, "source", source)
	}

	// Build the upstream TLS config once at startup (avoids re-reading CA file per connection).
	upstreamTLSCfg := UpstreamTLSConfig{
		Enabled:            *upstreamTLS,
		CAFile:             *upstreamCA,
		InsecureSkipVerify: *upstreamTLSInsecure,
		Dialer:             &net.Dialer{Timeout: *dialTimeout},
	}
	if err := upstreamTLSCfg.buildTLSConfig(); err != nil {
		slog.Error("failed to build upstream TLS config", "error", err)
		os.Exit(1)
	}
	if *upstreamTLSInsecure {
		slog.Warn("upstream TLS certificate verification is disabled")
	}

	cfg := ProxyConfig{
		Upstream:     *proxy,
		Provider:     provider,
		Pseudonym:    pseudonym,
		DialTimeout:  *dialTimeout,
		ReadTimeout:  *readTimeout,
		KeepAlive:    *keepAlive,
		IdleTimeout:  *idleTimeout,
		ConnectPorts: connectPorts,
		AllowedIPs:   allowList,
		NoProxy:      noProxy,
		Forwarding: ForwardingConfig{
			ForwardedEnabled:     *forwardedFlag,
			XForwardedForEnabled: *xForwardedForFlag,
		},
		UpstreamTLS: upstreamTLSCfg,
	}

	if *maxConns > 0 {
		l = netutil.LimitListener(l, *maxConns)
	}
	logArgs := []any{"addr", *addr, "proxy", *proxy, "via_pseudonym", pseudonym}
	if *maxConns > 0 {
		logArgs = append(logArgs, "max_conns", *maxConns)
	}
	slog.Info("listening", logArgs...)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				slog.Error("accept error", "error", err)
				continue
			}
			wg.Go(func() {
				handleClient(conn, cfg)
			})
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down, draining connections...")
	_ = l.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("all connections drained")
	case <-time.After(*drainTimeout):
		slog.Warn("drain timeout exceeded, forcing exit")
	}
	_ = provider.Close()
}
