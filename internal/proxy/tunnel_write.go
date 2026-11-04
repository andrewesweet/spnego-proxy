package proxy

import (
	"crypto/tls"
	"io"
	"net"
	"sync/atomic"
	"time"
)

type tunnelConn struct {
	net.Conn
	clock       atomic.Pointer[tunnelClock]
	writeClosed atomic.Bool
}

func (c *tunnelConn) Read(p []byte) (int, error) {
	clock := c.clock.Load()
	if clock == nil || clock.timeout <= 0 {
		return c.Conn.Read(p)
	}
	for {
		remaining := clock.remaining()
		if remaining <= 0 {
			return 0, errTunnelIdle
		}
		if err := c.SetReadDeadline(time.Now().Add(remaining)); err != nil {
			return 0, err
		}
		n, err := c.Conn.Read(p)
		if n > 0 {
			clock.touch()
		}
		if isTimeoutError(err) && !clock.idle() {
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *tunnelConn) Write(p []byte) (int, error) {
	clock := c.clock.Load()
	if clock == nil || clock.timeout <= 0 || c.writeClosed.Load() {
		return c.Conn.Write(p)
	}
	total := 0
	for len(p) > 0 {
		if err := c.SetWriteDeadline(time.Now().Add(clock.timeout)); err != nil {
			return total, err
		}
		n, err := writeTunnelChunk(c.Conn, p, clock.timeout)
		if n > 0 {
			clock.touch()
			total += n
			p = p[n:]
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}

func writeTunnelBuffered(conn net.Conn, p []byte, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		probe := time.Now().Add(timeout / 4)
		if deadline.Before(probe) {
			probe = deadline
		}
		if err := conn.SetWriteDeadline(probe); err != nil {
			return 0, err
		}
		n, err := conn.Write(p)
		if isTimeoutError(err) {
			if n > 0 {
				return n, nil
			}
			if time.Now().Before(deadline) {
				continue
			}
		}
		return n, err
	}
}

func (c *tunnelConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type upstreamTLSConn struct {
	*tls.Conn
	transport *tunnelConn
}

// CloseWrite half-closes the TLS connection. The close_notify alert is sent
// first, while the tunnel's write deadline still applies, so a peer that stops
// reading cannot make the alert write outlive the idle timeout. Only then is
// the write side marked closed, so later writes skip the deadline bookkeeping.
func (c *upstreamTLSConn) CloseWrite() error {
	err := c.Conn.CloseWrite()
	c.transport.writeClosed.Store(true)
	return err
}

func (c *upstreamTLSConn) Close() error {
	c.transport.writeClosed.Store(true)
	return c.Conn.Close()
}

func trackTunnelActivity(conn net.Conn, clock *tunnelClock) net.Conn {
	if clock.timeout <= 0 {
		return conn
	}
	if tc, ok := conn.(*upstreamTLSConn); ok {
		tc.transport.clock.Store(clock)
		return tc
	}
	c := &tunnelConn{Conn: conn}
	c.clock.Store(clock)
	return c
}
