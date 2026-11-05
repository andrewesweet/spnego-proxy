package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"testing"
)

type interimFuzzConn struct {
	net.Conn
	output bytes.Buffer
}

func (c *interimFuzzConn) Write(p []byte) (int, error) {
	return c.output.Write(p)
}

func FuzzReadThroughInterim(f *testing.F) {
	f.Add([]byte{0, 2, 3}, "POST", false, false)
	f.Add([]byte{3, 0}, "PUT", true, false)
	f.Add([]byte{0, 3}, "PATCH", false, false)
	f.Add([]byte{100, 102, 103, 199}, "POST", false, false)
	f.Add([]byte{103, 100}, "PUT", true, false)
	f.Add([]byte{100, 103}, "PATCH", false, true)
	f.Add([]byte{103}, "HEAD", true, true)
	f.Add([]byte{}, "GET", true, false)
	f.Add([]byte{}, "GET", false, true)

	f.Fuzz(func(t *testing.T, statuses []byte, method string, upgrade, http10 bool) {
		if len(statuses) > 32 {
			statuses = statuses[:32]
		}
		var upstream strings.Builder
		wantStatuses := make([]string, 0, len(statuses))
		for i, b := range statuses {
			code := 100 + int(b)%100
			if code == http.StatusSwitchingProtocols {
				code = http.StatusProcessing
			}
			status := fmt.Sprintf("HTTP/1.1 %d Interim", code)
			wantStatuses = append(wantStatuses, status)
			fmt.Fprintf(&upstream, "%s\r\nX-Interim: %d\r\n", status, i)
			if b&128 != 0 {
				upstream.WriteString("Content-Length: 0\r\n")
			} else if b&64 != 0 {
				upstream.WriteString("Transfer-Encoding: chunked\r\n")
			}
			if b&32 != 0 {
				upstream.WriteString("Trailer: X-Checksum\r\n")
			}
			upstream.WriteString("\r\n")
		}
		wantFinal := http.StatusOK
		if upgrade {
			wantFinal = http.StatusSwitchingProtocols
			upstream.WriteString("HTTP/1.1 101 Switching Protocols\r\nX-Final: stop\r\n\r\n")
		} else {
			upstream.WriteString("HTTP/1.1 200 OK\r\nX-Final: stop\r\nContent-Length: 0\r\n\r\n")
		}
		const remainder = "HTTP/1.1 204 No Content\r\n\r\ntunnel-bytes"
		upstream.WriteString(remainder)
		req := &http.Request{Method: method, ProtoMajor: 1, ProtoMinor: 1}
		if http10 {
			req.ProtoMinor = 0
		}
		reader := bufio.NewReader(strings.NewReader(upstream.String()))
		client := &interimFuzzConn{}
		resp, clientErr, err := readThroughInterim(client, req, func() (*http.Response, error) {
			return readUpstreamResponse(reader, req, testPseudonym)
		})
		if clientErr != nil || err != nil {
			t.Fatalf("interim sequence failed: client=%v upstream=%v", clientErr, err)
		}
		if resp == nil {
			t.Fatal("missing final response")
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != wantFinal || resp.Header.Get("X-Final") != "stop" {
			t.Fatalf("RFC 9110 section 15.2: stopped at %s, want marked final %d", resp.Status, wantFinal)
		}
		remaining, err := io.ReadAll(reader)
		if err != nil || string(remaining) != remainder {
			t.Fatalf("consumed bytes beyond final response: remaining=%q, error=%v", remaining, err)
		}
		if http10 {
			if client.output.Len() != 0 {
				t.Fatalf("RFC 9110 section 15.2: HTTP/1.0 received interim bytes %q", client.output.Bytes())
			}
			return
		}
		wire := textproto.NewReader(bufio.NewReader(&client.output))
		for i, wantStatus := range wantStatuses {
			status, err := wire.ReadLine()
			if err != nil || status != wantStatus {
				t.Fatalf("interim %d: got %q, %v; want %q", i, status, err, wantStatus)
			}
			header, err := wire.ReadMIMEHeader()
			if err != nil {
				t.Fatalf("interim %d headers: %v", i, err)
			}
			for _, name := range []string{"Content-Length", "Transfer-Encoding", "Trailer"} {
				if values, ok := header[name]; ok {
					t.Fatalf("RFC 9110 section 8.6; RFC 9112 sections 6.1, 6.3: interim %d emitted %s: %v", i, name, values)
				}
			}
			if header.Get("X-Interim") != strconv.Itoa(i) || !strings.Contains(header.Get("Via"), testPseudonym) {
				t.Fatalf("interim %d lost forwarded headers: %v", i, header)
			}
		}
		if extra, err := wire.R.ReadByte(); !errors.Is(err, io.EOF) {
			t.Fatalf("unexpected bytes after interim headers: byte=%q, error=%v", extra, err)
		}
	})
}

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

// FuzzContentLengthValues exercises validateResponseContentLength directly on
// adversarial multi-value / comma-list Content-Length header sets. It is a
// crash + tautology guard (the predicate re-derives the function's contract,
// so it is intentionally not a differential): never panic, and acceptance
// implies every non-empty comma part is a valid base-10 uint64 and all equal.
func FuzzContentLengthValues(f *testing.F) {
	f.Add("5")
	f.Add("5, 5")
	f.Add("5,6")
	f.Add("+5")
	f.Add("0x5")
	f.Add("042")
	f.Add(" 5 ")
	f.Add("5,,5")
	f.Add("")
	f.Add("18446744073709551616")
	f.Add("5\n5")
	f.Add("5\n6")

	f.Fuzz(func(t *testing.T, raw string) {
		// '\n'-separated header values; each value may itself be a comma list.
		values := strings.Split(raw, "\n")
		resp := &http.Response{Header: http.Header{headerContentLength: values}}

		accepted := validateResponseContentLength(resp) == nil
		if !accepted {
			return
		}

		var first uint64
		var seen bool
		for _, v := range values {
			for part := range strings.SplitSeq(v, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				n, err := strconv.ParseUint(part, 10, 64)
				if err != nil {
					t.Fatalf("accepted but part %q is not a base-10 uint64: raw=%q", part, raw)
				}
				if !seen {
					first, seen = n, true
				} else if n != first {
					t.Fatalf("accepted but parts disagree (%d != %d): raw=%q", n, first, raw)
				}
			}
		}
	})
}

// isTcharByte is an independent definition of the RFC 9110 §5.6.2 tchar
// production, written differently from isValidFieldName so it is a genuine
// oracle rather than a copy.
func isTcharByte(c byte) bool {
	if c >= '0' && c <= '9' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		return true
	}
	if c >= 'a' && c <= 'z' {
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// FuzzHeaderByteValidators is a self-referential property target (no external
// oracle — httpguts would add golang.org/x/text). It pins the two leaf
// response-splitting validators to independent byte-class definitions and
// checks that validateResponseHeaderBytes' boolean verdict is consistent with
// them. Only the boolean is asserted (validateResponseHeaderBytes ranges a map
// and the *blamed* header is non-deterministic; the nil/non-nil result is not).
func FuzzHeaderByteValidators(f *testing.F) {
	f.Add(headerContentType, "text/html")
	f.Add("X\x01", "v")
	f.Add("Set-Cookie", "a\rb")
	f.Add("Set-Cookie", "a\x7fb")
	f.Add("Set-Cookie", "a\tb")
	f.Add("Set-Cookie", "\x80\xff")
	f.Add("", "v")
	f.Add("ok", "")
	f.Add("a b", "v")

	f.Fuzz(func(t *testing.T, name, value string) {
		gotName := isValidFieldName(name)
		wantName := name != ""
		if wantName {
			for i := range len(name) {
				if !isTcharByte(name[i]) {
					wantName = false
					break
				}
			}
		}
		if gotName != wantName {
			t.Fatalf("isValidFieldName(%q)=%v, independent oracle=%v", name, gotName, wantName)
		}

		gotVal := hasForbiddenFieldValueByte(value)
		wantVal := false
		for i := range len(value) {
			b := value[i]
			if (b < 0x20 && b != '\t') || b == 0x7f {
				wantVal = true
				break
			}
		}
		if gotVal != wantVal {
			t.Fatalf("hasForbiddenFieldValueByte(%q)=%v, independent oracle=%v", value, gotVal, wantVal)
		}

		// Boolean consistency of the aggregate validator for a single header.
		resp := &http.Response{Header: http.Header{name: []string{value}}}
		gotAgg := validateResponseHeaderBytes(resp) != nil
		wantAgg := !gotName || gotVal
		if gotAgg != wantAgg {
			t.Fatalf("validateResponseHeaderBytes inconsistent: name=%q value=%q agg=%v want=%v",
				name, value, gotAgg, wantAgg)
		}
	})
}
