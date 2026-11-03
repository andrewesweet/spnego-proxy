//go:build unix

package proxy

import (
	"net"
	"os"
	"syscall"
)

func writeTunnelChunk(conn net.Conn, p []byte) (int, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return conn.Write(p[:1])
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var writeErr error
	err = raw.Write(func(fd uintptr) bool {
		for {
			n, writeErr = syscall.Write(int(fd), p)
			if writeErr != syscall.EINTR {
				return writeErr != syscall.EAGAIN && writeErr != syscall.EWOULDBLOCK
			}
		}
	})
	if err != nil {
		return 0, err
	}
	if writeErr != nil {
		return 0, os.NewSyscallError("write", writeErr)
	}
	return n, nil
}
