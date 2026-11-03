//go:build !unix

package proxy

import (
	"net"
	"time"
)

func writeTunnelChunk(conn net.Conn, p []byte, timeout time.Duration) (int, error) {
	return writeTunnelBuffered(conn, p, timeout)
}
