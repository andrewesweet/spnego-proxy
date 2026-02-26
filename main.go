// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"io"
	"log"
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

var logger = log.New(os.Stderr, "", log.LstdFlags)

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

// writeHTTPError sends a minimal HTTP error response to the client.
// It is best-effort; write failures are silently ignored because the
// connection is about to be closed.
func writeHTTPError(conn net.Conn, statusCode int, reason string) {
	resp := &http.Response{
		StatusCode:    statusCode,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}, "Connection": {"close"}},
		Body:          io.NopCloser(strings.NewReader(reason)),
		ContentLength: int64(len(reason)),
	}
	_ = resp.Write(conn)
}

func handleClient(conn net.Conn, proxy string, provider TokenProvider, debug bool, dialTimeout, readTimeout, keepAlive time.Duration) {
	defer func() { _ = conn.Close() }()
	if debug {
		defer logger.Printf("stop processing request for client: %v", conn.RemoteAddr())
		logger.Printf("new client: %v", conn.RemoteAddr())
	}
	proxyConn, err := net.DialTimeout("tcp", proxy, dialTimeout)
	if err != nil {
		logger.Printf("failed to connect to proxy: %v", err)
		writeHTTPError(conn, http.StatusBadGateway, "failed to connect to upstream proxy\n")
		return
	}
	defer func() { _ = proxyConn.Close() }()
	reqReader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	req, err := http.ReadRequest(reqReader)
	_ = conn.SetReadDeadline(time.Time{}) // clear after read
	if err != nil {
		if !errors.Is(err, io.EOF) {
			logger.Printf("failed to read request: %v", err)
			writeHTTPError(conn, http.StatusBadRequest, "failed to read client request\n")
		}
		return
	}
	token, err := provider.GetToken()
	if err != nil {
		logger.Printf("failed to get SPNEGO token: %v", err)
		writeHTTPError(conn, http.StatusBadGateway, "proxy authentication failed\n")
		return
	}
	if debug {
		logger.Printf("proxy request: %s %s %s (headers: %d)", req.Method, req.RequestURI, req.Proto, len(req.Header))
	}
	req.Header.Set("Proxy-Authorization", "Negotiate "+token)
	if err := req.WriteProxy(proxyConn); err != nil {
		logger.Printf("failed to write request to proxy: %v", err)
		writeHTTPError(conn, http.StatusBadGateway, "failed to relay request to upstream proxy\n")
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
		if debug {
			logger.Printf("forward start %v -> %v", fromAddr, toAddr)
			defer logger.Printf("forward done %v -> %v", fromAddr, toAddr)
		}
		if _, err := io.Copy(to, from); err != nil {
			logger.Printf("forward error %v -> %v: %v", fromAddr, toAddr, err)
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

	if *addr == "" || *proxy == "" {
		logger.Println("-addr and -proxy are required")
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
		logger.Fatal(err)
	}
	provider = NewCircuitBreakerTokenProvider(provider)

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatal(err)
	}
	if *maxConns > 0 {
		l = netutil.LimitListener(l, *maxConns)
		logger.Printf("listening on %s, proxying to %s (max connections: %d)", *addr, *proxy, *maxConns)
	} else {
		logger.Printf("listening on %s, proxying to %s", *addr, *proxy)
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
				logger.Printf("accept error: %v", err)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleClient(conn, *proxy, provider, *debug, *dialTimeout, *readTimeout, *keepAlive)
			}()
		}
	}()

	<-ctx.Done()
	logger.Println("shutting down, draining connections...")
	_ = l.Close()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		logger.Println("all connections drained")
	case <-time.After(*drainTimeout):
		logger.Println("drain timeout exceeded, forcing exit")
	}
	_ = provider.Close()
}
