package main

import (
	"bufio"
	"bytes"
	"net/http"
	"slices"
	"testing"
)

// FuzzUpstreamResponseFraming exercises the request-smuggling surface: if this
// proxy's response validators accept an upstream response, then serialising
// what we would forward and re-parsing it MUST yield identical body framing
// (Content-Length / Transfer-Encoding / connection-close). A divergence means
// the proxy and the downstream client would disagree on message length — a
// response-smuggling desync.
func FuzzUpstreamResponseFraming(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5,6\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nX-H: a\rb\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nX-H: a\x00b\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nX\x01Y: v\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		req := &http.Request{Method: "GET"}

		resp1, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), req)
		if err != nil {
			return
		}

		// Only the responses this proxy would actually forward are subject to
		// the framing-stability claim.
		if validateResponseContentLength(resp1) != nil || validateResponseHeaderBytes(resp1) != nil {
			_ = resp1.Body.Close()
			return
		}

		// Capture framing before resp.Write consumes the body.
		cl1 := resp1.ContentLength
		te1 := slices.Clone(resp1.TransferEncoding)
		close1 := resp1.Close

		var buf bytes.Buffer
		werr := resp1.Write(&buf)
		_ = resp1.Body.Close()
		if werr != nil {
			// Could not even serialise an accepted response: not a framing
			// claim — skip rather than emit a false positive.
			return
		}

		resp2, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(buf.Bytes())), req)
		if err != nil {
			t.Fatalf("accepted response failed to re-parse (smuggling desync): %v\nserialised=%q", err, buf.Bytes())
		}
		cl2 := resp2.ContentLength
		te2 := slices.Clone(resp2.TransferEncoding)
		close2 := resp2.Close
		_ = resp2.Body.Close()

		if cl1 != cl2 || close1 != close2 || !slices.Equal(te1, te2) {
			t.Fatalf("framing divergence after round-trip (smuggling):\n"+
				"  ContentLength %d -> %d\n  TransferEncoding %v -> %v\n  Close %v -> %v\n  input=%q",
				cl1, cl2, te1, te2, close1, close2, data)
		}
	})
}
