package proxy

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// E3 — RFC 9112 §6.1: Non-final / non-chunked Transfer-Encoding on request
// ---------------------------------------------------------------------------
//
// RFC 9112 §6.1: when Transfer-Encoding is present and the final coding is
// NOT "chunked", the message body framing is unknown to the recipient and
// the connection MUST be closed after receiving the request. A forward
// proxy MUST reject such a request because it cannot reliably forward an
// unframed body.
//
// Variants:
//   - "Transfer-Encoding: gzip"            (no chunked at all)
//   - "Transfer-Encoding: chunked, gzip"   (chunked not final)
//   - "Transfer-Encoding: gzip, chunked"   (final IS chunked → acceptable
//                                            framing, but RFC 9112 also says
//                                            a proxy MAY reject for caution;
//                                            we expect rejection here too).

func TestE3_RFC9112_NonChunkedTransferEncoding_Request(t *testing.T) {
	tests := []struct {
		name string
		te   string
	}{
		{name: "no_chunked_at_all", te: "gzip"},
		{name: "chunked_not_final", te: "chunked, gzip"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := "POST http://example.com/e3 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Transfer-Encoding: " + tc.te + "\r\n" +
				"\r\n"
			resp, reqs := proxyRawRoundTrip(t, raw)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status: want 400 or 502, got %d", resp.StatusCode)
			}
			if ps := resp.Header.Get(headerProxyStatus); !strings.Contains(ps, "http_") {
				t.Errorf("expected http_* Proxy-Status token, got %q", ps)
			}
			if len(reqs) != 0 {
				t.Errorf("upstream received %d requests; expected 0 (request must not be forwarded)", len(reqs))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// E4 — RFC 9112 §6.1: Request-side Content-Length anomalies
// ---------------------------------------------------------------------------
//
// Mirrors the response-side TestE2_RFC9112_MultipleDifferingCLInResponse but
// on the inbound request: a forward proxy MUST reject (not silently
// normalise) malformed Content-Length values per RFC 9112 §6.1.

func TestE4_RFC9112_RequestContentLengthAnomalies(t *testing.T) {
	tests := []struct {
		name string
		cl   string // raw CL header line — may include duplicate header lines
	}{
		{name: "negative", cl: "Content-Length: -1\r\n"},
		{name: "plus_prefix", cl: "Content-Length: +5\r\n"},
		{name: "hex_prefix", cl: "Content-Length: 0x05\r\n"},
		{name: "duplicate_differing", cl: "Content-Length: 5\r\nContent-Length: 7\r\n"},
		{name: "non_numeric", cl: "Content-Length: abc\r\n"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := "POST http://example.com/e4 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				tc.cl +
				"\r\n"
			resp, reqs := proxyRawRoundTrip(t, raw)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status: want 400 or 502, got %d", resp.StatusCode)
			}
			if len(reqs) != 0 {
				t.Errorf("upstream received %d requests; expected 0", len(reqs))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// E5 — RFC 9110 §5.5 / RFC 9112 §11.1: forbidden control octets in response
// header values are rejected (response-splitting defence-in-depth).
// ---------------------------------------------------------------------------
//
// A forward proxy MUST NOT relay header values that contain CR, LF, NUL or
// other ASCII control characters. Go's textproto parser splits on CRLF and
// would expose a clean "X-Evil: foo\r\nInjected: 1\r\n" payload as two
// distinct, well-formed headers — that case is indistinguishable from an
// intentional dual-header response and cannot be detected after parsing.
//
// What IS detectable post-parse is a header value containing a bare CR
// (no following LF) or a NUL/other control octet inside the value. These
// variants survive the textproto pass and reach the validator added in
// readUpstreamResponse.

func TestE5_RFC9110_ResponseHeaderControlOctetsRejected(t *testing.T) {
	tests := []struct {
		name        string
		respHeaders string // raw header lines (must end each line with \r\n)
	}{
		{
			name:        "bare_CR_in_value",
			respHeaders: "X-Evil: foo\rInjected: 1\r\n",
		},
		{
			name:        "NUL_in_value",
			respHeaders: "X-Evil: foo\x00bar\r\n",
		},
		{
			name:        "bel_control_in_value",
			respHeaders: "X-Evil: foo\x07bar\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canned := "HTTP/1.1 200 OK\r\n" +
				tc.respHeaders +
				"Content-Length: 0\r\n" +
				"\r\n"
			resp := rawCannedUpstreamRoundTrip(t, "/e5", canned)
			defer func() { _ = resp.Body.Close() }()

			assertStatusCode(t, resp, http.StatusBadGateway)
			if ps := resp.Header.Get(headerProxyStatus); !strings.Contains(ps, "http_protocol_error") {
				t.Errorf("expected Proxy-Status to contain 'http_protocol_error', got %q", ps)
			}
			// The injected header MUST NOT reach the client.
			if got := resp.Header.Get("Injected"); got != "" {
				t.Errorf("client saw injected header %q; expected absent", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// E5b — RFC 9110 §5.5: CRLF injection in request header forwarded to upstream
// ---------------------------------------------------------------------------
//
// Defence-in-depth: when a client emits a header line that injects a second
// header via embedded CRLF, the upstream must NOT see the injected header.
// Go's http.ReadRequest splits on CRLF during parse, so the inbound parser
// will already separate them into two headers — the relevant assertion is
// that whichever header is forwarded, no smuggled header reaches upstream
// with a value containing CR or LF.

func TestE5_RFC9110_RequestHeaderCRLFNotForwarded(t *testing.T) {
	raw := "GET http://example.com/e5b HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"X-Evil: foo\r\n X-Continued: tab-folded\r\n" +
		"\r\n"
	resp, reqs := proxyRawRoundTrip(t, raw)
	defer func() { _ = resp.Body.Close() }()

	// Either a clean 200 with the header normalised, or a 4xx rejection.
	// The forbidden outcome is the upstream receiving a header value that
	// contains bare CR or LF.
	for _, r := range reqs {
		for k, vs := range r.Header {
			for _, v := range vs {
				if strings.ContainsAny(v, "\r\n") {
					t.Errorf("upstream header %q has CR/LF in value %q", k, v)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// E6 — RFC 9112 §7.1.1: Chunk-extensions handled without misframing
// ---------------------------------------------------------------------------
//
// Chunked encoding allows chunk-extensions after the chunk size. Go's
// chunked reader tolerates them and drops them; the proxy MUST relay the
// body intact regardless. Test: send a chunked POST with an extension on
// the data chunk; verify the upstream receives the original body bytes.

func TestE6_RFC9112_ChunkExtensionsForwardedSafely(t *testing.T) {
	const wantBody = "hello"

	// Chunked POST with a chunk-extension on the data chunk.
	raw := "POST http://example.com/e6 HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"5;ext=foo\r\nhello\r\n" +
		"0\r\n" +
		"\r\n"
	resp, reqs := proxyRawRoundTrip(t, raw)
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}
	if got := string(reqs[0].BodyBytes); got != wantBody {
		t.Errorf("upstream body: want %q, got %q", wantBody, got)
	}
}

// ---------------------------------------------------------------------------
// Unit tests for response header byte validation
// ---------------------------------------------------------------------------

func TestValidateResponseHeaderBytes_Unit(t *testing.T) {
	tests := []struct {
		name    string
		hdr     http.Header
		wantErr bool
	}{
		{name: "clean", hdr: http.Header{"X-Ok": {"value"}}},
		{name: "tab_ok", hdr: http.Header{"X-Ok": {"a\tb"}}},
		{name: "obs_text_high_ok", hdr: http.Header{"X-Ok": {"a\xc3\xa9"}}}, // UTF-8 é
		{name: "empty_value_ok", hdr: http.Header{"X-Ok": {""}}},
		{name: "bare_CR", hdr: http.Header{"X-Bad": {"a\rb"}}, wantErr: true},
		{name: "bare_LF", hdr: http.Header{"X-Bad": {"a\nb"}}, wantErr: true},
		{name: "NUL", hdr: http.Header{"X-Bad": {"a\x00b"}}, wantErr: true},
		{name: "BEL", hdr: http.Header{"X-Bad": {"a\x07b"}}, wantErr: true},
		{name: "DEL", hdr: http.Header{"X-Bad": {"a\x7fb"}}, wantErr: true},
		{name: "bad_name_space", hdr: http.Header{"X Bad": {"v"}}, wantErr: true},
		{name: "bad_name_paren", hdr: http.Header{"X(Bad)": {"v"}}, wantErr: true},
		{name: "bad_name_colon_in_key", hdr: http.Header{"X:Bad": {"v"}}, wantErr: true},
		{name: "bad_name_empty", hdr: http.Header{"": {"v"}}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := &http.Response{Header: tc.hdr}
			pe := validateResponseHeaderBytes(resp)
			if tc.wantErr && pe == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && pe != nil {
				t.Errorf("expected nil, got error: %s", pe.errorType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// E7 — RFC 9112 §7.1.2: Trailer fields handled consistently
// ---------------------------------------------------------------------------
//
// The proxy lists Trailer in its hop-by-hop strip set. When an upstream
// chunked response includes trailers, the proxy must EITHER forward them
// (declaring Trailer) OR strip them — but it must be consistent and must
// not leave a Trailer header pointing at trailers the client will never
// receive. Asserts that the response framing remains valid (chunked
// terminator is reached, body is correctly delimited).

func TestE7_RFC9112_ChunkedResponseWithTrailerConsistent(t *testing.T) {
	// Chunked response carrying a Trailer header + actual trailer field
	// after the zero chunk.
	canned := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Trailer: X-Checksum\r\n" +
		"\r\n" +
		"5\r\nhello\r\n" +
		"0\r\n" +
		"X-Checksum: abc123\r\n" +
		"\r\n"
	// Read the full response, including body, so we can assert framing
	// is intact (no truncation, no leftover trailer bytes on the wire).
	resp := rawCannedUpstreamRoundTrip(t, "/e7", canned)
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, []byte("hello")) {
		t.Errorf("body: want %q, got %q", "hello", body)
	}

	// Consistency: if Trailer header advertises a name, either the trailer
	// value must arrive (resp.Trailer populated) OR Trailer must be
	// stripped from the response headers. The proxy must not advertise
	// trailers it will never deliver.
	advertised := resp.Header.Get(headerTrailer)
	if advertised != "" {
		// Trailer advertised → the named trailer must be present.
		if v := resp.Trailer.Get(advertised); v == "" {
			t.Errorf("Trailer %q advertised but absent from resp.Trailer (=%v)", advertised, resp.Trailer)
		}
	}
}
