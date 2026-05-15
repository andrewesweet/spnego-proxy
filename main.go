// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/net/netutil"
)

func init() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))
}

func main() {
	c, fs, err := parseFlags(os.Args[1:])
	if err != nil {
		// Mirror the historical flag.ExitOnError exit codes: -h/-help
		// exits 0, any other parse error exits 2. fs.Parse has already
		// written the error and usage to stderr.
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	if c.ShowVersion {
		fmt.Println(versionString())
		return
	}

	if c.Debug {
		logLevel.Set(slog.LevelDebug)
	}

	if c.Addr == "" || c.Proxy == "" {
		slog.Error("-addr and -proxy are required")
		fs.Usage()
		os.Exit(1)
	}

	provider, err := buildProvider(c)
	if err != nil {
		// codeql[go/clear-text-logging]
		slog.Error("failed to create token provider", "error", err)
		os.Exit(1)
	}

	l, err := net.Listen("tcp", c.Addr)
	if err != nil {
		slog.Error("failed to listen", "error", err, "addr", c.Addr)
		os.Exit(1)
	}
	pseudonym := generateViaPseudonym()

	connectPorts := splitCSV(c.ConnectPorts)

	allowList, err := parseAllowList(c.AllowedIPs)
	if err != nil {
		slog.Error("invalid -allowed-ips", "error", err)
		os.Exit(1)
	}

	noProxyPatterns := resolveNoProxy(c.NoProxy)
	var noProxy *NoProxyMatcher
	if noProxyPatterns != "" {
		noProxy = NewNoProxyMatcher(noProxyPatterns)
		source := "flag"
		if c.NoProxy == "" {
			source = "env"
		}
		slog.Info("noproxy bypass configured", "patterns", noProxyPatterns, "source", source)
	}

	// Build the upstream TLS config once at startup (avoids re-reading CA file per connection).
	upstreamTLSCfg := UpstreamTLSConfig{
		Enabled:            c.UpstreamTLS,
		CAFile:             c.UpstreamCA,
		InsecureSkipVerify: c.UpstreamTLSInsecure,
		Dialer:             &net.Dialer{Timeout: c.DialTimeout},
	}
	if err := upstreamTLSCfg.buildTLSConfig(); err != nil {
		slog.Error("failed to build upstream TLS config", "error", err)
		os.Exit(1)
	}
	if c.UpstreamTLSInsecure {
		slog.Warn("upstream TLS certificate verification is disabled")
	}

	cfg := ProxyConfig{
		Upstream:     c.Proxy,
		Provider:     provider,
		Pseudonym:    pseudonym,
		DialTimeout:  c.DialTimeout,
		ReadTimeout:  c.ReadTimeout,
		KeepAlive:    c.KeepAlive,
		IdleTimeout:  c.IdleTimeout,
		ConnectPorts: connectPorts,
		AllowedIPs:   allowList,
		NoProxy:      noProxy,
		Forwarding: ForwardingConfig{
			ForwardedEnabled:     c.Forwarded,
			XForwardedForEnabled: c.XForwardedFor,
		},
		UpstreamTLS: upstreamTLSCfg,
	}

	if c.MaxConns > 0 {
		l = netutil.LimitListener(l, c.MaxConns)
	}
	logArgs := []any{"addr", c.Addr, "proxy", c.Proxy, "via_pseudonym", pseudonym}
	if c.MaxConns > 0 {
		logArgs = append(logArgs, "max_conns", c.MaxConns)
	}
	slog.Info("listening", logArgs...)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	serve(ctx, l, cfg, c.DrainTimeout)
	_ = provider.Close()
}
