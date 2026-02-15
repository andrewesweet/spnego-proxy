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
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

// TokenProvider acquires SPNEGO tokens for proxy authentication.
type TokenProvider interface {
	// GetToken returns a base64-encoded SPNEGO token for the given proxy host.
	GetToken(proxyHost string) (string, error)
	// Close cleans up any resources.
	Close() error
}

func handleClient(conn net.Conn, proxy string, provider TokenProvider, debug bool) {
	defer func() { _ = conn.Close() }()
	if debug {
		defer logger.Printf("stop processing request for client: %v", conn.RemoteAddr())
		logger.Printf("new client: %v", conn.RemoteAddr())
	}

	reqReader := bufio.NewReader(conn)
	if debug {
		reqReader = bufio.NewReader(io.TeeReader(conn, logger.Writer()))
	}
	req, err := http.ReadRequest(reqReader)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			logger.Printf("failed to read request: %v", err)
		}
		return
	}

	forwardRequest(conn, reqReader, req, proxy, provider, debug)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "bind address")
	proxy := flag.String("proxy", "", "proxy address")
	spn := flag.String("spn", "", "service principal name (default: HTTP@<proxy-host>)")
	debug := flag.Bool("debug", false, "turn on debugging")

	followRedirects := flag.Bool("follow-redirects", false, "follow HTTP redirects on behalf of the client")
	maxRedirects := flag.Int("max-redirects", defaultMaxRedirects, "maximum number of redirects to follow")

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
	defer func() { _ = provider.Close() }()

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	logger.Printf("listening on %s, proxying to %s", *addr, *proxy)

	if *followRedirects {
		logger.Printf("redirect following enabled (max %d)", *maxRedirects)
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Fatal(err)
		}
		if *followRedirects {
			go handleClientFollowRedirects(conn, *proxy, provider, *maxRedirects, *debug)
		} else {
			go handleClient(conn, *proxy, provider, *debug)
		}
	}
}
