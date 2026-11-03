package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// startShutdownOrigin answers every request with 200 and a body naming the
// request path, so keep-alive survives a response and the next request can be
// observed. before, when non-nil, runs between reading a request and writing
// its response.
func startShutdownOrigin(t *testing.T, before func(*http.Request)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, req.Body)
					_ = req.Body.Close()
					if before != nil {
						before(req)
					}
					body := req.URL.Path
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// startServeForTest runs the real Serve on a loopback listener with the given
// drain timeout and returns its address, a shutdown function and a channel
// closed when Serve returns.
func startServeForTest(t *testing.T, cfg Config, drainTimeout time.Duration) (addr string, shutdown func(), served <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	servedCh := make(chan struct{})
	go func() {
		defer close(servedCh)
		Serve(ctx, ln, cfg, drainTimeout)
	}()
	var once sync.Once
	shutdown = func() { once.Do(cancel) }
	t.Cleanup(func() {
		shutdown()
		_ = ln.Close()
	})
	return ln.Addr().String(), shutdown, servedCh
}

// waitServe waits for Serve to return within d, reporting how long it took.
func waitServe(t *testing.T, served <-chan struct{}, d time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	select {
	case <-served:
		return time.Since(start)
	case <-time.After(d):
		t.Fatalf("Serve did not return within %v", d)
		return 0
	}
}

// bodyRequest writes one absolute-form GET to the client connection.
func bodyRequest(t *testing.T, conn net.Conn, path string) {
	t.Helper()
	if _, err := io.WriteString(conn, "GET http://example.test"+path+" HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestServeClosesIdleKeepAliveConnectionOnShutdown verifies that a connection
// idle between requests does not hold shutdown until its read deadline
// (defect D8): with a 30 s read timeout and a 10 s drain timeout, Serve
// returns as soon as the connection is closed rather than waiting for either.
func TestServeClosesIdleKeepAliveConnectionOnShutdown(t *testing.T) {
	cfg := defaultTestConfig(startShutdownOrigin(t, nil), &stubTokenProvider{token: "tok"})
	cfg.ReadTimeout = 30 * time.Second
	addr, shutdown, served := startServeForTest(t, cfg, 20*time.Second)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	bodyRequest(t, conn, "/one")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("response: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != "/one" {
		t.Fatalf("response body = %q, want /one", got)
	}

	// The connection is now idle between requests: no request in flight.
	shutdown()
	if elapsed := waitServe(t, served, 5*time.Second); elapsed > time.Second {
		t.Errorf("Serve returned %v after shutdown with only an idle connection; want it to close the idle connection at once", elapsed)
	}
}

// TestServeEndsBusyConnectionWithConnectionClose verifies that a connection
// with a request in flight when shutdown starts is ended after that
// response, and that the response tells the client so with Connection: close
// (defect D8), instead of serving further requests until the drain timeout.
func TestServeEndsBusyConnectionWithConnectionClose(t *testing.T) {
	seen := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	cfg := defaultTestConfig(startShutdownOrigin(t, func(*http.Request) {
		once.Do(func() { close(seen) })
		<-release
	}), &stubTokenProvider{token: "tok"})
	cfg.ReadTimeout = 30 * time.Second
	addr, shutdown, served := startServeForTest(t, cfg, 20*time.Second)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	bodyRequest(t, conn, "/slow")
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("origin did not receive the request")
	}

	// The request is in flight at the origin, so the session is busy when
	// shutdown starts.
	shutdown()
	close(release)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("response in flight: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(got) != "/slow" {
		t.Errorf("response body = %q, want /slow (the request in flight must be answered)", got)
	}
	if !resp.Close {
		// http.ReadResponse reports a wire "Connection: close" as
		// Response.Close on an HTTP/1.1 response with a Content-Length, and
		// strips the header, so this asserts the header reached the client.
		t.Errorf("the response sent during shutdown does not end the connection: want Connection: close")
	}

	// The connection must end after that response, and a later request on it
	// must not be served.
	bodyRequest(t, conn, "/after")
	if late, err := http.ReadResponse(br, nil); err == nil {
		_ = late.Body.Close()
		t.Errorf("served %s on a connection shut down mid-request; want the connection closed", late.Status)
	}
	if elapsed := waitServe(t, served, 5*time.Second); elapsed > time.Second {
		t.Errorf("Serve returned %v after shutdown with one request in flight; want it to end that connection after its response", elapsed)
	}
}

// failingListener fails every Accept with EMFILE, as accept(2) does when the
// process has run out of file descriptors. It records the time of every call
// so a test can measure the delay between retries.
type failingListener struct {
	net.Listener
	stamps chan time.Time
}

func newFailingListener(t *testing.T) *failingListener {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	return &failingListener{Listener: inner, stamps: make(chan time.Time, 64)}
}

func (f *failingListener) Accept() (net.Conn, error) {
	select {
	case f.stamps <- time.Now():
	default:
	}
	return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
}

// TestAcceptBackoffDoublesToMaxAndResets pins the retry schedule: an Accept
// error is followed by a 5 ms wait, doubling up to a 1 s ceiling, and a
// successful Accept resets the wait to 5 ms. This is the schedule
// net/http.Server.Serve uses, and it is what stops a persistent error (EMFILE)
// from spinning the loop at full speed.
func TestAcceptBackoffDoublesToMaxAndResets(t *testing.T) {
	var b acceptBackoff
	want := []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
		80 * time.Millisecond,
		160 * time.Millisecond,
		320 * time.Millisecond,
		640 * time.Millisecond,
		time.Second,
		time.Second,
		time.Second,
	}
	for i, w := range want {
		if got := b.next(); got != w {
			t.Fatalf("next() call %d = %v, want %v", i+1, got, w)
		}
	}
	b.reset()
	if got := b.next(); got != 5*time.Millisecond {
		t.Fatalf("next() after reset = %v, want 5ms", got)
	}
}

// TestServeBacksOffOnPersistentAcceptError is the regression test for the
// accept-loop spin: with a listener that always fails, the loop must keep
// retrying on the specified doubling schedule. Before the fix the loop retried
// with no wait at all and managed ~160,000 Accept calls and log lines per 100 ms.
// Cancellation must also interrupt the capped 1 s wait. Virtual time makes both
// assertions independent of scheduler load.
func TestServeBacksOffOnPersistentAcceptError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l := newFailingListener(t)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() { Serve(ctx, l, Config{}, time.Second); close(done) }()
		defer func() {
			cancel()
			<-done
		}()

		previous := <-l.stamps
		for i, want := range []time.Duration{
			5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond,
			40 * time.Millisecond, 80 * time.Millisecond, 160 * time.Millisecond,
			320 * time.Millisecond, 640 * time.Millisecond, time.Second, time.Second,
		} {
			select {
			case stamp := <-l.stamps:
				if got := stamp.Sub(previous); got != want {
					t.Fatalf("retry %d interval = %v, want %v", i+1, got, want)
				}
				previous = stamp
			case <-time.After(2 * time.Second):
				t.Fatalf("Serve stopped retrying before retry %d", i+1)
			}
		}

		// Ensure the accept loop is blocked in its capped retry wait before
		// cancelling; cancellation at the next Accept would miss this path.
		synctest.Wait()
		cancel()
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("Serve did not interrupt the 1s retry wait within 100ms of cancellation")
		}
	})
}

// TestServeResetsAcceptBackoffAfterSuccess pins the reset half of the
// schedule through Serve itself: after a successful Accept the next error must
// wait 5 ms again, not continue the doubled delay.
func TestServeResetsAcceptBackoffAfterSuccess(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })
	l := &scriptedListener{Listener: inner, successAt: 7, stamps: make(chan time.Time, 64)}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { Serve(ctx, l, Config{}, 100*time.Millisecond); close(done) }()
	defer func() {
		cancel()
		<-done
	}()

	// Six failures, one success, then two more failures. With the wait doubling
	// from 5 ms the seventh call arrives after 5+10+20+40+80+160 = 315 ms, and
	// without the reset the next wait would be 320 ms rather than 5 ms.
	var stamps []time.Time
	deadline := time.After(5 * time.Second)
	for len(stamps) < 9 {
		select {
		case ts := <-l.stamps:
			stamps = append(stamps, ts)
		case <-deadline:
			t.Fatalf("only %d Accept calls observed, want 9", len(stamps))
		}
	}

	beforeSuccess := stamps[6].Sub(stamps[5])
	if beforeSuccess < 120*time.Millisecond {
		t.Fatalf("gap before the 6th retry = %v, want >= 120ms (backoff doubling, not a spin)", beforeSuccess)
	}
	afterSuccess := stamps[8].Sub(stamps[7])
	if afterSuccess > 100*time.Millisecond {
		t.Fatalf("gap after a successful Accept = %v, want ~5ms (reset), not a continued backoff", afterSuccess)
	}
}

// scriptedListener fails every Accept except the successAt-th call, which
// returns an already-closed connection so the accepted handler exits at once.
type scriptedListener struct {
	net.Listener
	calls     atomic.Int64
	successAt int64
	stamps    chan time.Time
}

func (s *scriptedListener) Accept() (net.Conn, error) {
	n := s.calls.Add(1)
	select {
	case s.stamps <- time.Now():
	default:
	}
	if n == s.successAt {
		c, peer := net.Pipe()
		_ = peer.Close()
		return c, nil
	}
	return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
}
