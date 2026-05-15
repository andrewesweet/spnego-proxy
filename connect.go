package main

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
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

// idleCopy copies from src to dst, resetting the read deadline on srcConn
// after each successful read. If no data arrives within timeout, the read
// fails with a deadline error and the copy returns. A zero timeout disables
// the idle check and falls back to plain io.Copy.
func idleCopy(dst net.Conn, src io.Reader, srcConn net.Conn, timeout time.Duration) (int64, error) {
	if timeout <= 0 {
		return io.Copy(dst, src)
	}
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	buf := *bufp
	var total int64
	for {
		_ = srcConn.SetReadDeadline(time.Now().Add(timeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			nw, writeErr := dst.Write(buf[:n])
			total += int64(nw)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			_ = srcConn.SetReadDeadline(time.Time{}) // clear deadline
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

// forwardHalf copies data from src to dst, calling CloseWrite on dst when
// done. It logs the start, completion, and any errors. Callers use
// wg.Go to launch forwardHalf so the WaitGroup is managed automatically.
// When idleTimeout > 0, idleCopy is used with srcConn to enforce an idle
// deadline; otherwise plain io.Copy is used and srcConn may be nil.
func forwardHalf(dst net.Conn, src io.Reader, srcConn net.Conn, fromAddr, toAddr net.Addr, idleTimeout time.Duration) {
	defer closeWrite(dst)
	slog.Debug("forward start", "from", fromAddr, "to", toAddr)
	defer slog.Debug("forward done", "from", fromAddr, "to", toAddr)
	var err error
	if idleTimeout > 0 {
		_, err = idleCopy(dst, src, srcConn, idleTimeout)
	} else {
		_, err = io.Copy(dst, src)
	}
	if err != nil {
		if isExpectedCloseError(err) {
			slog.Debug("forward closed", "error", err, "from", fromAddr, "to", toAddr)
		} else {
			slog.Error("forward error", "error", err, "from", fromAddr, "to", toAddr)
		}
	}
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
			if isExpectedCloseError(err) {
				slog.Debug("forward closed", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			} else {
				slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
			}
		}
		slog.Debug("upstream rejected CONNECT", "status", resp.StatusCode, "client_addr", clientAddr)
		return
	}

	// For 2xx CONNECT responses, write a raw status line instead of using
	// resp.Write, which emits Content-Length: 0 and Connection: close —
	// headers that cause Bun/undici clients to close the connection before
	// the TLS handshake through the tunnel can begin.
	if err := writeConnectOK(conn, resp); err != nil {
		if isExpectedCloseError(err) {
			slog.Debug("forward closed", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		} else {
			slog.Error("forward error", "error", err, "from", proxyConn.RemoteAddr(), "to", conn.RemoteAddr())
		}
		return
	}

	slog.Debug("CONNECT tunnel established", "client_addr", clientAddr, "upstream_addr", proxyConn.RemoteAddr())
	var wg sync.WaitGroup
	wg.Go(func() {
		forwardHalf(proxyConn, reqReader, conn, conn.RemoteAddr(), proxyConn.RemoteAddr(), idleTimeout)
	})
	wg.Go(func() {
		forwardHalf(conn, upstreamReader, proxyConn, proxyConn.RemoteAddr(), conn.RemoteAddr(), idleTimeout)
	})
	wg.Wait()
}
