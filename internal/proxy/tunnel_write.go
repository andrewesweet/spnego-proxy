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
		if err := c.Conn.SetReadDeadline(time.Now().Add(remaining)); err != nil {
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
		if err := c.Conn.SetWriteDeadline(time.Now().Add(clock.timeout)); err != nil {
			return total, err
		}
		n, err := writeTunnelChunk(c.Conn, p)
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

func (c *upstreamTLSConn) CloseWrite() error {
	c.transport.writeClosed.Store(true)
	return c.Conn.CloseWrite()
}

func (c *upstreamTLSConn) Close() error {
	c.transport.writeClosed.Store(true)
	return c.Conn.Close()
}

func trackTunnelActivity(conn net.Conn, clock *tunnelClock) net.Conn {
	if tc, ok := conn.(*upstreamTLSConn); ok {
		tc.transport.clock.Store(clock)
		return tc
	}
	c := &tunnelConn{Conn: conn}
	c.clock.Store(clock)
	return c
}
