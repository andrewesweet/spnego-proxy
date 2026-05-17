package proxy

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Serve runs the accept loop until ctx is cancelled, then drains in-flight
// connections. On cancellation the listener is closed and the function waits
// up to drainTimeout for active handleClient goroutines to finish before
// returning. The listener is assumed to already have any concurrency limit
// (netutil.LimitListener) applied by the caller.
func Serve(ctx context.Context, l net.Listener, cfg Config, drainTimeout time.Duration) {
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
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
			wg.Go(func() {
				handleClient(conn, cfg)
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
