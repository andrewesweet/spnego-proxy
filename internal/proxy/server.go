package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Accept-error retry schedule, mirroring net/http.Server.Serve: the first
// error waits 5ms and each further error doubles the wait, up to 1s. A
// successful Accept resets the wait. Without the wait a persistent error such
// as EMFILE (too many open files) spins the loop on a CPU core and writes one
// log line per attempt.
const (
	acceptBackoffInitial = 5 * time.Millisecond
	acceptBackoffMax     = time.Second
)

// acceptBackoff computes how long the accept loop waits before retrying after
// an error.
type acceptBackoff struct{ delay time.Duration }

// next starts at acceptBackoffInitial, then doubles the previous wait on each
// call, capped at acceptBackoffMax.
func (b *acceptBackoff) next() time.Duration {
	if b.delay == 0 {
		b.delay = acceptBackoffInitial
	} else if b.delay *= 2; b.delay > acceptBackoffMax {
		b.delay = acceptBackoffMax
	}
	return b.delay
}

// reset restores the initial wait after a successful Accept.
func (b *acceptBackoff) reset() { b.delay = 0 }

// Serve runs the accept loop until ctx is cancelled, then drains in-flight
// connections. On cancellation the listener is closed and the function waits
// up to drainTimeout for active session goroutines to finish before
// returning. The listener is assumed to already have any concurrency limit
// (netutil.LimitListener) applied by the caller.
func Serve(ctx context.Context, l net.Listener, cfg Config, drainTimeout time.Duration) {
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		var backoff acceptBackoff
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
				}
				delay := backoff.next()
				slog.Error("accept error", "error", err, "retry_in", delay)
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
				continue
			}
			backoff.reset()
			wg.Go(func() {
				handleClientCtx(ctx, conn, cfg)
			})
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down, draining connections...")
	_ = l.Close()
	// Wait for the accept loop to observe the closed listener and stop
	// before draining: this guarantees no further wg.Go can race with the
	// wg.Wait below (a sync.WaitGroup add concurrent with Wait is a misuse).
	<-acceptDone

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("all connections drained")
	case <-time.After(drainTimeout):
		slog.Warn("drain timeout exceeded, forcing exit")
	}
}
