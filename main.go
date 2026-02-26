// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
)

var logLevel = new(slog.LevelVar) // default Info

func init() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	})))
}

// extractHost returns the host portion of addr, stripping any port suffix.
// If addr has no port, it is returned unchanged.
func extractHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// normalizeSPN converts an explicit SPN between GSS-API hostbased format
// (service@host) and Kerberos principal format (service/host) so the user
// need not know which backend is active. targetSep is the separator the
// active backend expects ('@' for GSS-API, '/' for gokrb5); alternateSep
// is the other backend's separator.
func normalizeSPN(spn string, targetSep, alternateSep byte) string {
	if strings.IndexByte(spn, targetSep) >= 0 {
		return spn // already contains the target separator
	}
	if i := strings.IndexByte(spn, alternateSep); i >= 0 {
		return spn[:i] + string(targetSep) + spn[i+1:]
	}
	return spn // no recognized separator; return as-is
}

// TokenProvider acquires SPNEGO tokens for proxy authentication.
type TokenProvider interface {
	// GetToken returns a base64-encoded SPNEGO token.
	GetToken() (string, error)
	// Close cleans up any resources.
	Close() error
}

// enableKeepAlive enables TCP keepalive on conn with the given period.
// Non-TCP connections (e.g. net.Pipe in tests) are silently skipped.
func enableKeepAlive(conn net.Conn, period time.Duration) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(period)
	}
}

// RFC 9209 Proxy-Status error tokens used by this proxy.
// Only tokens that correspond to actual proxy error paths are defined.
const (
	proxyErrConnectionTimeout    = "connection_timeout"
	proxyErrConnectionRefused    = "connection_refused"
	proxyErrHTTPRequestError     = "http_request_error"
	proxyErrProxyInternalError   = "proxy_internal_error"
	proxyErrConnectionTerminated = "connection_terminated"
)

// writeHTTPError sends a minimal HTTP error response to the client with an
// RFC 9209 Proxy-Status header indicating the error type. It is best-effort;
// write failures are silently ignored because the connection is about to be
// closed.
func writeHTTPError(conn net.Conn, statusCode int, proxyStatusError string, reason string) {
	header := http.Header{
		"Content-Type": {"text/plain"},
		"Connection":   {"close"},
	}
	// RFC 9209 Proxy-Status header with RFC 8941 Structured Fields syntax.
	header.Set("Proxy-Status", "spnego-proxy; error="+proxyStatusError)

	resp := &http.Response{
		StatusCode:    statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(reason)),
		ContentLength: int64(len(reason)),
	}
	_ = resp.Write(conn)
}

func handleClient(conn net.Conn, proxy string, provider TokenProvider, dialTimeout, readTimeout, keepAlive time.Duration) {
	defer func() { _ = conn.Close() }()
	clientAddr := conn.RemoteAddr().String()
	slog.Debug("new client", "client_addr", clientAddr)
	defer slog.Debug("stop processing request", "client_addr", clientAddr)
	proxyConn, err := net.DialTimeout("tcp", proxy, dialTimeout)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			slog.Error("failed to connect to proxy", "error", err, "error_type", proxyErrConnectionTimeout, "client_addr", clientAddr, "upstream_addr", proxy)
			writeHTTPError(conn, http.StatusGatewayTimeout, proxyErrConnectionTimeout, "failed to connect to upstream proxy\n")
		} else {
			slog.Error("failed to connect to proxy", "error", err, "error_type", proxyErrConnectionRefused, "client_addr", clientAddr, "upstream_addr", proxy)
			writeHTTPError(conn, http.StatusBadGateway, proxyErrConnectionRefused, "failed to connect to upstream proxy\n")
		}
		return
	}
	defer func() { _ = proxyConn.Close() }()
	reqReader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	req, err := http.ReadRequest(reqReader)
	_ = conn.SetReadDeadline(time.Time{}) // clear after read
	if err != nil {
		if !errors.Is(err, io.EOF) {
			slog.Error("failed to read request", "error", err, "error_type", proxyErrHTTPRequestError, "client_addr", clientAddr)
			writeHTTPError(conn, http.StatusBadRequest, proxyErrHTTPRequestError, "failed to read client request\n")
		}
		return
	}
	token, err := provider.GetToken()
	if err != nil {
		slog.Error("failed to get SPNEGO token", "error", err, "error_type", proxyErrProxyInternalError, "client_addr", clientAddr, "upstream_addr", proxy, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, http.StatusBadGateway, proxyErrProxyInternalError, "proxy authentication failed\n")
		return
	}
	slog.Debug("proxy request", "method", req.Method, "uri", req.RequestURI, "proto", req.Proto, "headers", len(req.Header), "client_addr", clientAddr, "upstream_addr", proxy)
	req.Header.Set("Proxy-Authorization", "Negotiate "+token)
	if err := req.WriteProxy(proxyConn); err != nil {
		slog.Error("failed to write request to proxy", "error", err, "error_type", proxyErrConnectionTerminated, "client_addr", clientAddr, "upstream_addr", proxy, "method", req.Method, "host", req.Host)
		writeHTTPError(conn, http.StatusBadGateway, proxyErrConnectionTerminated, "failed to relay request to upstream proxy\n")
		return
	}
	if keepAlive > 0 {
		enableKeepAlive(conn, keepAlive)
		enableKeepAlive(proxyConn, keepAlive)
	}
	var wg sync.WaitGroup
	forward := func(from io.Reader, to net.Conn, fromAddr, toAddr net.Addr) {
		defer wg.Done()
		defer func() {
			if cw, ok := to.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		slog.Debug("forward start", "from", fromAddr, "to", toAddr)
		defer slog.Debug("forward done", "from", fromAddr, "to", toAddr)
		if _, err := io.Copy(to, from); err != nil {
			slog.Error("forward error", "error", err, "from", fromAddr, "to", toAddr)
		}
	}
	wg.Add(2)
	go forward(reqReader, proxyConn, conn.RemoteAddr(), proxyConn.RemoteAddr())
	go forward(proxyConn, conn, proxyConn.RemoteAddr(), conn.RemoteAddr())
	wg.Wait()
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
	maxConns := flag.Int("max-conns", 512, "maximum number of concurrent connections (0 for unlimited)")

	// Flags for gokrb5 password-based auth (optional on macOS, required on other platforms)
	cfgFile := flag.String("config", "", "kerberos config file")
	user := flag.String("user", "", "kerberos user name")
	realm := flag.String("realm", "", "kerberos realm")
	passwordFile := flag.String("password-file", "", "password file path")
	flag.Parse()

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
	provider = NewCircuitBreakerTokenProvider(provider)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		slog.Error("failed to listen", "error", err, "addr", *addr)
		os.Exit(1)
	}
	if *maxConns > 0 {
		l = netutil.LimitListener(l, *maxConns)
		slog.Info("listening", "addr", *addr, "proxy", *proxy, "max_conns", *maxConns)
	} else {
		slog.Info("listening", "addr", *addr, "proxy", *proxy)
	}

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
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleClient(conn, *proxy, provider, *dialTimeout, *readTimeout, *keepAlive)
			}()
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
