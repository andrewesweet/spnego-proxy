package proxy

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// enableKeepAlive enables TCP keepalive on conn with the given period.
// Non-TCP connections (e.g. net.Pipe in tests) are silently skipped.
func enableKeepAlive(conn net.Conn, period time.Duration) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(period)
	}
}

// closeWrite calls CloseWrite on conn if the underlying type supports it.
// This signals the remote peer that no more data will be sent on this half
// of the connection, allowing it to read EOF and finish gracefully.
func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// errTunnelIdle reports that a CONNECT tunnel was closed because neither of
// its directions made observable transport progress for the whole idle timeout.
var errTunnelIdle = errors.New("tunnel idle timeout")

// tunnelClock measures idleness for a whole CONNECT tunnel rather than for a
// single direction: both halves record observed transport progress in the same
// timestamp.
type tunnelClock struct {
	timeout time.Duration
	origin  time.Time
	last    atomic.Int64 // Nanoseconds since origin of the latest observed transport progress
}

// newTunnelClock returns a clock measuring idleness against timeout. A timeout
// of zero disables the idle check.
func newTunnelClock(timeout time.Duration) *tunnelClock {
	return &tunnelClock{timeout: timeout, origin: time.Now()}
}

// touch records observed transport progress.
func (c *tunnelClock) touch() { c.touchAt(time.Since(c.origin)) }

func (c *tunnelClock) touchAt(elapsed time.Duration) {
	now := int64(elapsed)
	for last := c.last.Load(); now > last; last = c.last.Load() {
		if c.last.CompareAndSwap(last, now) {
			return
		}
	}
}

// quietFor reports how long the tunnel has had no observed transport progress.
func (c *tunnelClock) quietFor() time.Duration {
	return c.quietForSince(time.Since)
}

func (c *tunnelClock) quietForSince(since func(time.Time) time.Duration) time.Duration {
	for {
		last := c.last.Load()
		elapsed := since(c.origin)
		if c.last.Load() == last {
			return elapsed - time.Duration(last)
		}
	}
}

// idle reports whether neither direction made observed progress for the timeout.
func (c *tunnelClock) idle() bool { return c.quietFor() >= c.timeout }

// remaining reports how much of the idle budget is left before the tunnel is
// considered idle in both directions. It is not positive once the budget is
// spent.
func (c *tunnelClock) remaining() time.Duration { return c.timeout - c.quietFor() }

// idleCopy copies from src to dst while the tunnel as a whole stays active.
//
// Before each read it arms the read deadline on srcConn from the tunnel's
// remaining idle budget, and after each successful read it records the traffic
// in clock. A read that times out only ends the copy when neither direction
// has made observable transport progress within the timeout; otherwise the
// loop rearms the deadline. Destination connections arm a deadline before each
// transport write and record bytes accepted for writing. A one-way transfer
// stays open while this progress occurs within the timeout. TCP window
// withholding beyond the timeout counts as inactivity even if the remote
// application continues reading. A zero timeout disables the idle check and
// falls back to plain io.Copy.
func idleCopy(dst net.Conn, src io.Reader, srcConn net.Conn, clock *tunnelClock) (int64, error) {
	if clock.timeout <= 0 {
		return io.Copy(dst, src)
	}
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	buf := *bufp
	var total int64
	for {
		remaining := clock.remaining()
		if remaining <= 0 {
			return total, errTunnelIdle
		}
		_ = srcConn.SetReadDeadline(time.Now().Add(remaining))
		n, readErr := src.Read(buf)
		if n > 0 {
			clock.touch()
			nw, writeErr := dst.Write(buf[:n])
			total += int64(nw)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			_ = srcConn.SetReadDeadline(time.Time{}) // clear deadline
			if isTimeoutError(readErr) {
				if !clock.idle() {
					continue // the other direction is still moving data
				}
				return total, errTunnelIdle
			}
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}

// isExpectedCloseError reports whether err is a normal connection-teardown
// error that does not warrant ERROR-level logging. EOF, broken pipe,
// connection reset, and use-of-closed-connection are all routine in proxy
// forwarding — one side simply closed first.
func isExpectedCloseError(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	return false
}

// isTimeoutError reports whether err is a deadline expiry. In a tunnel copy a
// timeout means the idle timeout or a write deadline did its job, which is
// routine teardown rather than a proxy fault.
func isTimeoutError(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// logForwardError logs a data-forwarding error at the appropriate level:
// Debug for routine connection teardown (see isExpectedCloseError), an idle
// timeout, or a write deadline expiry; Error otherwise. It is a no-op when err
// is nil.
func logForwardError(err error, fromAddr, toAddr net.Addr) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, errTunnelIdle):
		slog.Debug("tunnel closed after idle timeout", "from", fromAddr, "to", toAddr)
	case isTimeoutError(err), isExpectedCloseError(err):
		slog.Debug("forward closed", "error", err, "from", fromAddr, "to", toAddr)
	default:
		slog.Error("forward error", "error", err, "from", fromAddr, "to", toAddr)
	}
}

// forwardHalf copies data from src to dst, calling CloseWrite on dst when
// done. It logs the start, completion, and any errors. Callers use
// wg.Go to launch forwardHalf so the WaitGroup is managed automatically.
// The clock is shared by both halves of the tunnel, so the idle timeout is
// measured across the tunnel as a whole; a disabled clock turns idleCopy into
// plain io.Copy.
func forwardHalf(dst net.Conn, src io.Reader, srcConn net.Conn, fromAddr, toAddr net.Addr, clock *tunnelClock) error {
	slog.Debug("forward start", "from", fromAddr, "to", toAddr)
	defer slog.Debug("forward done", "from", fromAddr, "to", toAddr)
	_, err := idleCopy(dst, src, srcConn, clock)
	logForwardError(err, fromAddr, toAddr)
	if err == nil {
		closeWrite(dst)
	}
	return err
}

// forwardTunnel copies both directions until both halves finish. Reuse the
// existing readers so payload buffered while reading HTTP headers is preserved.
func forwardTunnel(conn, peerConn net.Conn, reqReader, peerReader *bufio.Reader, idleTimeout time.Duration) {
	clock := newTunnelClock(idleTimeout)
	conn = trackTunnelActivity(conn, clock)
	peerConn = trackTunnelActivity(peerConn, clock)
	forward := func(dst net.Conn, src *bufio.Reader, srcConn net.Conn) {
		if err := forwardHalf(dst, src, srcConn, srcConn.RemoteAddr(), dst.RemoteAddr(), clock); err != nil {
			for _, c := range []net.Conn{conn, peerConn} {
				if tc, ok := c.(*upstreamTLSConn); ok {
					_ = tc.transport.Close()
				}
				_ = c.Close()
			}
		}
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		forward(peerConn, reqReader, conn)
	})
	wg.Go(func() {
		forward(conn, peerReader, peerConn)
	})
	wg.Wait()
}

// handleConnectTunnel manages the CONNECT tunnel lifecycle per RFC 9110 §9.3.6.
// It reads the upstream response before forwarding any client payload (D6),
// relays the response to the client (D7), and then starts bidirectional
// forwarding only after a 2xx is confirmed.
func handleConnectTunnel(conn, proxyConn net.Conn, reqReader *bufio.Reader, req *http.Request, pseudonym, clientAddr string, idleTimeout time.Duration) {
	upstreamReader := bufio.NewReader(proxyConn)
	resp, err := readUpstreamResponse(upstreamReader, req, pseudonym) //nolint:bodyclose // S3: resp.Body is the raw tunnel stream; closing it would shut down the TCP connection we forward below.
	if err != nil {
		handleUpstreamResponseError(conn, proxyConn, err, clientAddr)
		return
	}

	// D7 (RFC 9110 §9.3.6): relay the upstream's actual response to the
	// client. We never synthesise our own 2xx here.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Upstream rejected the CONNECT — forward the full response
		// including any rejection body (e.g. HTML error page).
		// Non-2xx is terminal, so Content-Length/Connection are fine.
		// Connection is cleaned up by deferred conn.Close() in
		// handleClient (D5).
		if err := resp.Write(conn); err != nil {
			logForwardError(err, proxyConn.RemoteAddr(), conn.RemoteAddr())
		}
		slog.Debug("upstream rejected CONNECT", "status", resp.StatusCode, "client_addr", clientAddr)
		return
	}

	// For 2xx CONNECT responses, write a raw status line instead of using
	// resp.Write, which emits Content-Length: 0 and Connection: close —
	// headers that cause Bun/undici clients to close the connection before
	// the TLS handshake through the tunnel can begin.
	if err := writeConnectOK(conn, resp); err != nil {
		logForwardError(err, proxyConn.RemoteAddr(), conn.RemoteAddr())
		return
	}

	slog.Debug("CONNECT tunnel established", "client_addr", clientAddr, "upstream_addr", proxyConn.RemoteAddr())
	forwardTunnel(conn, proxyConn, reqReader, upstreamReader, idleTimeout)
}
