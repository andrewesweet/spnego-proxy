package proxy

import (
	"bufio"
	"net"
)

// ClientSession holds the per-connection state for one accepted client
// connection. Exactly one ClientSession is constructed per handleClient
// invocation and lives for the duration of that connection.
//
// It replaces the previous convention of threading the
// (conn, cfg, clientAddr) tuple — plus the lazily-dialled upstream
// connection and its reader — through every per-connection handler as bare
// parameters. The per-request *http.Request is NOT session state: it varies
// every keep-alive iteration and stays a method parameter.
//
// Ownership rules (enforced by structure, previously by convention):
//   - conn is owned by handleClient, which retains the close/closeWrite
//     defers in their original LIFO order (issue #75).
//   - reqReader is created exactly once over conn and reused on every
//     keep-alive iteration; recreating it would drop buffered bytes for
//     pipelined requests.
//   - proxyConn / upstreamReader are lazily dialled on the first
//     via-upstream plain-HTTP request and reused on subsequent ones
//     (RFC 4559 §5); they are closed by the handleClient defer. The
//     CONNECT-via-upstream and noproxy-direct flows use their own
//     method-local connections and never touch these fields.
//   - cfg is a read-only value snapshot, identical to the previous
//     pass-by-value Config parameter.
type ClientSession struct {
	conn       net.Conn
	cfg        Config
	clientAddr string

	reqReader *bufio.Reader

	proxyConn      net.Conn
	upstreamReader *bufio.Reader
}
