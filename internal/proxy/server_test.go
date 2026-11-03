package proxy

import (
	"context"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// failingListener fails every Accept with EMFILE, as accept(2) does when the
// process has run out of file descriptors. It records the time of every call
// so a test can measure the delay between retries.
type failingListener struct {
	net.Listener
	calls  atomic.Int64
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
	f.calls.Add(1)
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
// retrying but at a bounded rate. Before the fix the loop retried with no wait
// at all and managed ~160,000 Accept calls and log lines per 100 ms.
func TestServeBacksOffOnPersistentAcceptError(t *testing.T) {
	l := newFailingListener(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { Serve(ctx, l, Config{}, time.Second); close(done) }()

	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of cancellation")
	}

	calls := l.calls.Load()
	if calls < 3 {
		t.Fatalf("%d Accept calls in 150ms, want the loop to keep retrying (at least 3)", calls)
	}
	if calls > 40 {
		t.Fatalf("%d Accept calls in 150ms, want a backed-off rate (5ms doubling to 1s), not a spin", calls)
	}
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
