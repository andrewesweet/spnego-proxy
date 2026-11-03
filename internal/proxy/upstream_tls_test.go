package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type pacedTLSConn struct {
	net.Conn
	interval time.Duration
}

func (c *pacedTLSConn) Write(p []byte) (int, error) {
	if c.interval == 0 {
		return c.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		n, err := c.Conn.Write(p[:min(128, len(p))])
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		time.Sleep(c.interval)
	}
	return total, nil
}

func TestTunnelTLSRecordProgressAfterHalfClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 500 * time.Millisecond
		certPEM, keyPEM := generateTestCert(t)
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(certPEM) {
			t.Fatal("add test TLS root")
		}
		clientRaw, serverRaw := net.Pipe()
		t.Cleanup(func() { _ = clientRaw.Close() })
		t.Cleanup(func() { _ = serverRaw.Close() })
		_ = clientRaw.SetDeadline(time.Now().Add(20 * time.Second))
		_ = serverRaw.SetDeadline(time.Now().Add(20 * time.Second))
		transport := &tunnelConn{Conn: clientRaw}
		client := &upstreamTLSConn{
			Conn: tls.Client(transport, &tls.Config{
				RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
			}),
			transport: transport,
		}
		paced := &pacedTLSConn{Conn: serverRaw}
		server := tls.Server(paced, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		handshakeDone := make(chan error, 1)
		go func() { handshakeDone <- server.Handshake() }()
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-handshakeDone; err != nil {
			t.Fatal(err)
		}
		paced.interval = timeout / 4
		payload := strings.Repeat("record payload", 256)
		serverDone := make(chan struct{})
		var serverErr error
		go func() {
			defer close(serverDone)
			defer func() { _ = server.Close() }()
			if _, serverErr = io.Copy(io.Discard, server); serverErr != nil {
				return
			}
			_, serverErr = io.WriteString(server, payload)
		}()
		defer func() {
			_ = clientRaw.Close()
			_ = serverRaw.Close()
			<-serverDone
		}()
		transport.clock.Store(newTunnelClock(timeout))
		if err := client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(timeout))
		start := time.Now()
		got, err := io.ReadAll(client)
		if err != nil || string(got) != payload {
			t.Fatalf("TLS record with transport progress after half-close: received %d/%d bytes, error %v", len(got), len(payload), err)
		}
		if elapsed := time.Since(start); elapsed <= timeout {
			t.Fatalf("TLS record completed in %v, want longer than %v", elapsed, timeout)
		}
		<-serverDone
		if serverErr != nil {
			t.Fatalf("TLS record write: %v", serverErr)
		}
	})
}

func TestDialUpstreamTLSHandshakeTimeout(t *testing.T) {
	for _, limit := range []string{"timeout", "deadline"} {
		t.Run(limit, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			serverDone := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					serverDone <- err
					return
				}
				defer func() { _ = conn.Close() }()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, err = io.Copy(io.Discard, conn)
				serverDone <- err
			}()
			dialer := &net.Dialer{}
			if limit == "timeout" {
				dialer.Timeout = 50 * time.Millisecond
			} else {
				dialer.Deadline = time.Now().Add(50 * time.Millisecond)
			}
			conn, err := dialUpstream(ln.Addr().String(), UpstreamTLSConfig{Enabled: true, Dialer: dialer})
			if conn != nil {
				_ = conn.Close()
				t.Fatal("TLS dial succeeded without a server handshake")
			}
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("TLS handshake error = %v, want timeout", err)
			}
			if err := <-serverDone; err != nil {
				t.Fatalf("TLS dial did not close the connection on timeout: %v", err)
			}
		})
	}
}

func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}

func TestUpstreamTLSConnection(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	tlsListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tlsListener.Close() }()

	ctx := t.Context()

	// Accept one connection and respond with 200 OK.
	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Unblock blocking I/O when the test context is cancelled.
		go func() {
			<-ctx.Done()
			_ = conn.SetDeadline(time.Now())
		}()

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()
		resp := &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader("ok")),
			ContentLength: 2,
		}
		_ = resp.Write(conn)
	}()

	// Write CA cert to temp file.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	proxy := NewProxyUnderTest(t, tlsListener.Addr().String())
	proxy.SetUpstreamTLS(UpstreamTLSConfig{
		Enabled: true,
		CAFile:  caFile,
	})
	t.Cleanup(proxy.Close)

	raw := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)
}

func TestUpstreamPlainTCPDefault(t *testing.T) {
	raw := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp, _ := proxyRawRoundTrip(t, raw)
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)
}
