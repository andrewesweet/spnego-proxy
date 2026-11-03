package proxy

// response_test.go — unit tests for the shared upstream-response helpers.

import (
	"errors"
	"net"
	"net/http"
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
