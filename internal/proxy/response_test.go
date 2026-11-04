package proxy

// response_test.go — unit tests for the shared upstream-response helpers.

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestD3_InterimResponseHeaderBytesValidated verifies that a 1xx interim
// response whose header value carries a forbidden octet is never serialized to
// the client, even when the response did not come from http.ReadResponse.
//
// readThroughInterim serializes an interim response by hand (framing headers
// removed) instead of through resp.Write, so it must validate the header bytes
// first, exactly as readUpstreamResponse does for the upstream path
// (RFC 9110 §5.5, RFC 9112 §11.1). Go's parser rejects most such content
// itself today; this pins the guarantee for any response object that reaches
// the helper, including the -noproxy path, which has no wider response
// validation.
func TestD3_InterimResponseHeaderBytesValidated(t *testing.T) {
	client, peer := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = peer.Close() }()

	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	interim := &http.Response{
		Status:     "103 Early Hints",
		StatusCode: http.StatusEarlyHints,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"X-Evil": {"foo\rInjected: 1"}},
		Body:       http.NoBody,
	}
	final := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	reads := 0
	readOne := func() (*http.Response, error) {
		reads++
		if reads == 1 {
			return interim, nil
		}
		return final, nil
	}

	// Nothing may reach the client: the interim response carries a bare CR,
	// so it must be rejected before serialization.
	received := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		_ = peer.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := peer.Read(buf)
		received <- string(buf[:n])
	}()

	resp, clientErr, rerr := readThroughInterim(client, req, readOne)
	// Closing the client end unblocks the reader above: on a rejected interim
	// response nothing was serialized, so the read ends at once with EOF
	// instead of holding the test until the deadline.
	_ = client.Close()
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if !errors.Is(rerr, errMalformedResponse) {
		t.Fatalf("readThroughInterim error = %v, want errMalformedResponse", rerr)
	}
	if resp != nil || clientErr != nil {
		t.Fatalf("readThroughInterim = (resp %v, clientWriteErr %v), want both nil", resp, clientErr)
	}
	if reads != 1 {
		t.Errorf("readOne called %d times, want 1: reading must stop at the rejected interim response", reads)
	}
	if got := <-received; got != "" {
		t.Errorf("client received %q, want nothing: a rejected interim response must not be serialized", got)
	}
}

// writeCancellationReleaser is a net.Conn that signals when exchangeRequest
// cancels an in-flight Expect upload, so a test can hold the upload pending and
// finish it at exactly that moment instead of sleeping.
type writeCancellationReleaser struct {
	net.Conn
	release func()
}

func (c writeCancellationReleaser) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		c.release()
	}
	return c.Conn.SetWriteDeadline(t)
}

// TestD3_ExpectRaceDoesNotReuseConnection verifies that a final response which
// arrives while an Expect: 100-continue upload is still being written leaves the
// connection non-reusable.
//
// The upstream can answer early (for example 417 Expectation Failed) without
// reading the request body. Those unwritten body bytes stay ahead of the next
// request on the upstream connection, so reusing it would answer that request
// from the wrong message. Both relay paths stop on connectionWillClose, which
// must therefore report true whenever the response beat the upload.
func TestD3_ExpectRaceDoesNotReuseConnection(t *testing.T) {
	client, clientPeer := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = clientPeer.Close() }()
	upstream, upstreamPeer := net.Pipe()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = upstreamPeer.Close() }()
	// net.Pipe is synchronous; drain both far ends so deadline changes and any
	// write below cannot block.
	go func() { _, _ = io.Copy(io.Discard, clientPeer) }()
	go func() { _, _ = io.Copy(io.Discard, upstreamPeer) }()

	req := &http.Request{
		Method:     http.MethodPost,
		URL:        &url.URL{Scheme: "http", Host: "example.test", Path: "/upload"},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Expect": {"100-continue"}},
		Body:       io.NopCloser(strings.NewReader("hello")),
	}
	final := &http.Response{
		Status:     "417 Expectation Failed",
		StatusCode: http.StatusExpectationFailed,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}
	release := make(chan struct{})
	var once sync.Once
	releaseUpload := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseUpload) // never leave the upload goroutine blocked

	// The upload stays pending until exchangeRequest cancels it, and that
	// cancellation is the only thing that releases it. The response therefore
	// wins the race by construction, with no wall-clock timing involved.
	writeRequest := func() error {
		<-release
		return nil
	}

	resp, writeErr, clientErr, err := exchangeRequest(client, writeCancellationReleaser{Conn: upstream, release: releaseUpload}, req, writeRequest, func() (*http.Response, error) {
		return final, nil
	})
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil || clientErr != nil || writeErr != nil {
		t.Fatalf("exchangeRequest = (err %v, clientWriteErr %v, requestWriteErr %v), want all nil", err, clientErr, writeErr)
	}
	if resp == nil {
		t.Fatal("exchangeRequest returned no response, want the early final response")
	}
	if !connectionWillClose(req, resp) {
		t.Errorf("connectionWillClose = false, want true: a final response that beat the Expect upload must not reuse the connection")
	}
}
