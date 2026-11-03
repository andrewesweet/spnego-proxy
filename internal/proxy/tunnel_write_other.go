//go:build !unix

package proxy

import "net"

func writeTunnelChunk(conn net.Conn, p []byte) (int, error) {
	return conn.Write(p[:1])
}
