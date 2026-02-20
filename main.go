// Package main implements a local TCP proxy that injects SPNEGO authentication
// headers into HTTP requests forwarded to an upstream proxy.
package main

import (
	"bufio"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

// TokenProvider acquires SPNEGO tokens for proxy authentication.
type TokenProvider interface {
	// GetToken returns a base64-encoded SPNEGO token for the given proxy host.
	GetToken(proxyHost string) (string, error)
	// Close cleans up any resources.
	Close() error
}

func handleClient(conn net.Conn, proxy string, provider TokenProvider, debug bool, dialTimeout, readTimeout time.Duration) {
	defer func() { _ = conn.Close() }()
	if debug {
		defer logger.Printf("stop processing request for client: %v", conn.RemoteAddr())
		logger.Printf("new client: %v", conn.RemoteAddr())
	}
	proxyConn, err := net.DialTimeout("tcp", proxy, dialTimeout)
	if err != nil {
		logger.Printf("failed to connect to proxy: %v", err)
		return
	}
	defer func() { _ = proxyConn.Close() }()
	reqReader := bufio.NewReader(conn)
	if debug {
		reqReader = bufio.NewReader(io.TeeReader(conn, os.Stdout))
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	req, err := http.ReadRequest(reqReader)
	_ = conn.SetReadDeadline(time.Time{}) // clear after read
	if err != nil {
		if !errors.Is(err, io.EOF) {
			logger.Printf("failed to read request: %v", err)
		}
		return
	}
	token, err := provider.GetToken(proxy)
	if err != nil {
		logger.Printf("failed to get SPNEGO token: %v", err)
		return
	}
	req.Header.Set("Proxy-Authorization", "Negotiate "+token)
	if debug {
		if err := req.WriteProxy(io.MultiWriter(proxyConn, os.Stdout)); err != nil {
			logger.Printf("failed to write request to proxy: %v", err)
			return
		}
	} else {
		if err := req.WriteProxy(proxyConn); err != nil {
			logger.Printf("failed to write request to proxy: %v", err)
			return
		}
	}
	var wg sync.WaitGroup
	forward := func(from, to net.Conn) {
		defer wg.Done()
		defer func() {
			if cw, ok := to.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
		}()
		if debug {
			fromAddr, toAddr := from.RemoteAddr(), to.RemoteAddr()
			logger.Printf("forward start %v -> %v", fromAddr, toAddr)
			defer logger.Printf("forward done %v -> %v", fromAddr, toAddr)
		}
		if _, err := io.Copy(to, from); err != nil {
			logger.Printf("forward error %v -> %v: %v", from.RemoteAddr(), to.RemoteAddr(), err)
		}
	}
	wg.Add(2)
	go forward(conn, proxyConn)
	go forward(proxyConn, conn)
	wg.Wait()
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "bind address")
	proxy := flag.String("proxy", "", "proxy address")
	spn := flag.String("spn", "", "service principal name (default: HTTP@<proxy-host>)")
	debug := flag.Bool("debug", false, "turn on debugging")

	dialTimeout := flag.Duration("dial-timeout", 30*time.Second, "timeout for connecting to upstream proxy")
	readTimeout := flag.Duration("read-timeout", 30*time.Second, "timeout for reading client HTTP request")

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
	defer func() { _ = provider.Close() }()

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	logger.Printf("listening on %s, proxying to %s", *addr, *proxy)

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Printf("accept error: %v", err)
			continue
		}
		go handleClient(conn, *proxy, provider, *debug, *dialTimeout, *readTimeout)
	}
}
