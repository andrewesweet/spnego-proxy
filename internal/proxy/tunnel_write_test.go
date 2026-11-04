package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type countedTunnelConn struct {
	net.Conn
	writes    atomic.Int64
	deadlines atomic.Int64
	readFroms atomic.Int64
}

func (c *countedTunnelConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func (c *countedTunnelConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlines.Add(1)
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *countedTunnelConn) ReadFrom(src io.Reader) (int64, error) {
	c.readFroms.Add(1)
	return io.Copy(c.Conn, src)
}

func TestTunnelBufferedWriteBatchesPayload(t *testing.T) {
	sender, receiver := net.Pipe()
	t.Cleanup(func() { _ = sender.Close() })
	t.Cleanup(func() { _ = receiver.Close() })
	counted := &countedTunnelConn{Conn: sender}
	conn := trackTunnelActivity(counted, newTunnelClock(5*time.Second))
	payload := bytes.Repeat([]byte("0123456789abcdef"), 64*1024)
	writeDone := make(chan error, 1)
	go func() {
		n, err := conn.Write(payload)
		if err == nil && n != len(payload) {
			err = io.ErrShortWrite
		}
		writeDone <- err
	}()
	_ = receiver.SetReadDeadline(time.Now().Add(10 * time.Second))
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(receiver, got); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("buffered forwarding changed the payload")
	}
	if calls := counted.writes.Load(); calls == 0 || calls > 64 {
		t.Fatalf("1 MiB transfer used %d writes, want at most 64", calls)
	}
	if calls := counted.deadlines.Load(); calls > 1024 {
		t.Fatalf("1 MiB transfer used %d deadline updates, want at most 1024", calls)
	}
}

type pacedTLSReadConn struct {
	net.Conn
	interval time.Duration
}

func (c *pacedTLSReadConn) Read(p []byte) (int, error) {
	if c.interval > 0 {
		time.Sleep(c.interval)
		p = p[:min(len(p), 128)]
	}
	return c.Conn.Read(p)
}

func TestTunnelBufferedWritePreservesTLSRecordWithTransportProgress(t *testing.T) {
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
		sender, receiver := net.Pipe()
		t.Cleanup(func() { _ = sender.Close() })
		t.Cleanup(func() { _ = receiver.Close() })
		_ = sender.SetDeadline(time.Now().Add(20 * time.Second))
		_ = receiver.SetDeadline(time.Now().Add(20 * time.Second))
		counted := &countedTunnelConn{Conn: sender}
		transport := &tunnelConn{Conn: counted}
		client := tls.Client(transport, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})
		paced := &pacedTLSReadConn{Conn: receiver}
		server := tls.Server(paced, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		handshakeDone := make(chan error, 1)
		go func() { handshakeDone <- server.Handshake() }()
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-handshakeDone; err != nil {
			t.Fatal(err)
		}
		counted.writes.Store(0)
		counted.deadlines.Store(0)
		paced.interval = timeout / 4
		transport.clock.Store(newTunnelClock(timeout))
		payload := bytes.Repeat([]byte("0123456789abcdef"), 64)
		got := make([]byte, len(payload))
		readDone := make(chan error, 1)
		go func() {
			defer close(readDone)
			_, err := io.ReadFull(server, got)
			readDone <- err
		}()
		defer func() {
			_ = sender.Close()
			_ = receiver.Close()
			<-readDone
		}()
		start := time.Now()
		if n, err := client.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("TLS record write with transport progress: %d/%d bytes, %v", n, len(payload), err)
		}
		if err := <-readDone; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("buffered partial writes changed the TLS payload")
		}
		if elapsed := time.Since(start); elapsed <= timeout {
			t.Fatalf("TLS record completed in %v, want longer than %v", elapsed, timeout)
		}
		if calls := counted.writes.Load(); calls == 0 || calls > 64 {
			t.Fatalf("1 KiB TLS record used %d writes, want at most 64", calls)
		}
	})
}

func TestTunnelDisabledTimeoutPreservesOptimizedCopy(t *testing.T) {
	for _, timeout := range []time.Duration{0, -time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			client, conn, peer, upstream := newTunnelTestConnections(t, "pipe")
			clientSide := &countedTunnelConn{Conn: conn}
			upstreamSide := &countedTunnelConn{Conn: peer}
			tunnelDone := make(chan struct{})
			go func() {
				defer close(tunnelDone)
				forwardTunnel(clientSide, upstreamSide, bufio.NewReader(clientSide), bufio.NewReader(upstreamSide), timeout)
			}()
			for _, direction := range []struct {
				src net.Conn
				dst net.Conn
			}{{client, upstream}, {upstream, client}} {
				writeDone := make(chan error, 1)
				go func() {
					_, err := io.WriteString(direction.src, "payload")
					writeDone <- err
				}()
				got := make([]byte, len("payload"))
				if _, err := io.ReadFull(direction.dst, got); err != nil || string(got) != "payload" {
					t.Fatalf("disabled-timeout forwarding: %q, %v", got, err)
				}
				if err := <-writeDone; err != nil {
					t.Fatal(err)
				}
			}
			_ = client.Close()
			_ = upstream.Close()
			select {
			case <-tunnelDone:
			case <-time.After(5 * time.Second):
				t.Fatal("disabled-timeout tunnel did not stop")
			}
			for _, c := range []*countedTunnelConn{clientSide, upstreamSide} {
				if calls := c.readFroms.Load(); calls == 0 {
					t.Error("disabled-timeout tunnel hid the connection's optimized copy interface")
				}
				if calls := c.deadlines.Load(); calls != 0 {
					t.Errorf("disabled-timeout tunnel set %d write deadlines", calls)
				}
			}
		})
	}
}
