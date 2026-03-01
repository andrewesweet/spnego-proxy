package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// RecordedRequest
// ---------------------------------------------------------------------------

// RecordedRequest stores an HTTP request received by MockUpstreamProxy along
// with its body bytes.  The original body is drained during processing so that
// the connection is not blocked; the captured bytes are available via BodyBytes.
type RecordedRequest struct {
	*http.Request
	BodyBytes []byte
}

// ---------------------------------------------------------------------------
// MockUpstreamProxy
// ---------------------------------------------------------------------------

// MockUpstreamProxy is a programmable mock upstream proxy for white-box
// integration testing.  It listens on a dynamic TCP port, records every
// incoming HTTP request, and responds according to a configurable
// ResponseFunc.
//
// A nil ResponseFunc return simulates a premature connection closure.
type MockUpstreamProxy struct {
	listener     net.Listener
	responseFunc func(*http.Request) *http.Response

	mu       sync.Mutex
	requests []*RecordedRequest

	wg     sync.WaitGroup
	closed chan struct{}
}

// NewMockUpstreamProxy creates and starts a mock upstream on a dynamic port.
// If responseFunc is nil a default 200 OK with an empty body is used.
func NewMockUpstreamProxy(t *testing.T, responseFunc func(*http.Request) *http.Response) *MockUpstreamProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("MockUpstreamProxy: listen: %v", err)
	}
	if responseFunc == nil {
		responseFunc = defaultMockResponse
	}
	m := &MockUpstreamProxy{
		listener:     l,
		responseFunc: responseFunc,
		closed:       make(chan struct{}),
	}
	m.wg.Go(m.acceptLoop)
	return m
}

func defaultMockResponse(_ *http.Request) *http.Response {
	return &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          http.NoBody,
		ContentLength: 0,
	}
}

func (m *MockUpstreamProxy) acceptLoop() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.closed:
				return
			default:
			}
			continue
		}
		m.wg.Go(func() { m.handleConn(conn) })
	}
}

func (m *MockUpstreamProxy) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// Drain and capture the request body so the sender is unblocked and
	// the bytes are available for later assertions.
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}

	m.mu.Lock()
	m.requests = append(m.requests, &RecordedRequest{
		Request:   req,
		BodyBytes: bodyBytes,
	})
	m.mu.Unlock()

	resp := m.responseFunc(req)
	if resp == nil {
		// nil signals the test wants the connection closed without a
		// response, simulating a premature upstream closure.
		return
	}
	if resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	_ = resp.Write(conn)
}

// Addr returns the listener address (host:port).
func (m *MockUpstreamProxy) Addr() string {
	return m.listener.Addr().String()
}

// Requests returns a snapshot of all recorded requests.
func (m *MockUpstreamProxy) Requests() []*RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*RecordedRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

// Close shuts down the listener and waits for in-flight connections to drain.
func (m *MockUpstreamProxy) Close() {
	close(m.closed)
	_ = m.listener.Close()
	m.wg.Wait()
}

// ---------------------------------------------------------------------------
// ProxyUnderTest
// ---------------------------------------------------------------------------

// ProxyUnderTest starts handleClient goroutines on a dynamic-port listener
// backed by a stubTokenProvider.  It removes the per-test boilerplate of
// creating listeners, token providers, and pseudonyms.
//
// The Provider field may be customised after construction but before the
// first client connects. ConnectPorts and Forwarding must be set via
// SetConnectPorts and SetForwardingConfig to avoid data races with the
// accept loop goroutine.
type ProxyUnderTest struct {
	listener net.Listener

	// Provider is the stub token provider shared with cfg.Provider.
	// Tests may mutate its fields (e.g., Provider.err) but must NOT replace
	// the pointer — cfg.Provider would still reference the old value.
	Provider *stubTokenProvider

	// mu protects cfg so mutable fields (ConnectPorts, Forwarding) can
	// be set after construction without a data race with acceptLoop.
	mu  sync.RWMutex
	cfg ProxyConfig

	wg     sync.WaitGroup
	closed chan struct{}
}

// getConfig returns a snapshot of the current ProxyConfig (thread-safe).
func (p *ProxyUnderTest) getConfig() ProxyConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cfg
}

// SetConnectPorts sets the allowed CONNECT port list.
// Thread-safe; may be called at any time after construction.
func (p *ProxyUnderTest) SetConnectPorts(ports []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.ConnectPorts = ports
}

// SetForwardingConfig sets the ForwardingConfig.
// Thread-safe; may be called at any time after construction.
func (p *ProxyUnderTest) SetForwardingConfig(fwd ForwardingConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.Forwarding = fwd
}

// SetIdleTimeout sets the idle timeout for CONNECT tunnels.
// Thread-safe; may be called at any time after construction.
func (p *ProxyUnderTest) SetIdleTimeout(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.IdleTimeout = d
}

// SetAllowedIPs sets the IP allowlist for client access control.
// Thread-safe; may be called at any time after construction.
func (p *ProxyUnderTest) SetAllowedIPs(ips []*net.IPNet) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.AllowedIPs = ips
}

// SetUpstreamTLS sets the upstream TLS configuration.
// Thread-safe; may be called at any time after construction.
func (p *ProxyUnderTest) SetUpstreamTLS(cfg UpstreamTLSConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg.UpstreamTLS = cfg
}

// NewProxyUnderTest creates and starts a proxy listening on a dynamic port.
// upstream is the address of the mock upstream to forward to.
func NewProxyUnderTest(t *testing.T, upstream string) *ProxyUnderTest {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ProxyUnderTest: listen: %v", err)
	}
	provider := &stubTokenProvider{token: "test-token"}
	p := &ProxyUnderTest{
		listener: l,
		Provider: provider,
		cfg: ProxyConfig{
			Upstream:    upstream,
			Provider:    provider,
			Pseudonym:   testPseudonym,
			DialTimeout: 5 * time.Second,
			ReadTimeout: 5 * time.Second,
			KeepAlive:   0,
		},
		closed: make(chan struct{}),
	}
	p.wg.Go(p.acceptLoop)
	return p
}

func (p *ProxyUnderTest) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
			}
			continue
		}
		p.wg.Go(func() {
			handleClient(conn, p.getConfig())
		})
	}
}

// Addr returns the proxy's listener address (host:port).
func (p *ProxyUnderTest) Addr() string {
	return p.listener.Addr().String()
}

// Close stops accepting new connections and waits for in-flight connections
// to drain.
func (p *ProxyUnderTest) Close() {
	close(p.closed)
	_ = p.listener.Close()
	p.wg.Wait()
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

// assertHeaderPresent fails the test if header[key] != expectedValue.
func assertHeaderPresent(t *testing.T, header http.Header, key, expectedValue string) {
	t.Helper()
	if got := header.Get(key); got != expectedValue {
		t.Errorf("header %q: want %q, got %q", key, expectedValue, got)
	}
}

// assertHeaderAbsent fails the test if header[key] is present.  It uses a
// direct map lookup so that present-but-empty headers are detected correctly
// (header.Get returns "" for both absent and empty).
func assertHeaderAbsent(t *testing.T, header http.Header, key string) {
	t.Helper()
	if vals, ok := header[http.CanonicalHeaderKey(key)]; ok {
		t.Errorf("header %q: want absent, got %q", key, vals)
	}
}

// assertStatusCode fails the test if resp.StatusCode != expected.
func assertStatusCode(t *testing.T, resp *http.Response, expected int) {
	t.Helper()
	if resp.StatusCode != expected {
		t.Errorf("status code: want %d, got %d", expected, resp.StatusCode)
	}
}

// proxyRoundTrip sends a GET request with the given headers through a fresh
// proxy→upstream chain and returns the upstream's recorded request.  It
// assumes the default 200 OK mock response. Optional setup funcs can
// configure the ProxyUnderTest before the first request (e.g., SetForwardingConfig).
func proxyRoundTrip(t *testing.T, headers http.Header, setup ...func(*ProxyUnderTest)) *RecordedRequest {
	t.Helper()
	upstream := NewMockUpstreamProxy(t, nil)
	t.Cleanup(upstream.Close)

	proxy := NewProxyUnderTest(t, upstream.Addr())
	for _, fn := range setup {
		fn(proxy)
	}
	t.Cleanup(proxy.Close)

	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	_ = resp.Body.Close()
	assertStatusCode(t, resp, http.StatusOK)

	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}
	return reqs[0]
}

// proxyRawRoundTrip creates a fresh upstream+proxy pair, sends the given raw
// HTTP request bytes through the proxy, and returns the response and recorded
// upstream requests. Optional setup funcs can configure the ProxyUnderTest
// before the first request (e.g., SetConnectPorts).
func proxyRawRoundTrip(t *testing.T, rawReq string, setup ...func(*ProxyUnderTest)) (*http.Response, []*RecordedRequest) {
	t.Helper()
	return proxyRawRoundTripWithUpstream(t, rawReq, nil, setup...)
}

// proxyRawRoundTripWithUpstream is like proxyRawRoundTrip but accepts a custom
// upstream response function. If respFunc is nil, the default 200 OK mock is
// used.
func proxyRawRoundTripWithUpstream(t *testing.T, rawReq string, respFunc func(*http.Request) *http.Response, setup ...func(*ProxyUnderTest)) (*http.Response, []*RecordedRequest) {
	t.Helper()
	upstream := NewMockUpstreamProxy(t, respFunc)
	t.Cleanup(upstream.Close)
	proxy := NewProxyUnderTest(t, upstream.Addr())
	for _, fn := range setup {
		fn(proxy)
	}
	t.Cleanup(proxy.Close)
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp, upstream.Requests()
}

// waitForDone waits for a done channel to be closed, failing the test if it
// does not close within 5 seconds. This replaces the repeated
// select { case <-done: case <-time.After(5*time.Second): t.Fatal(...) }
// pattern used in tests that launch handleClient in a goroutine.
func waitForDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleClient did not return within 5s")
	}
}

// defaultTestConfig returns a ProxyConfig suitable for most tests. The
// upstream address and provider are required; all other fields use sensible
// defaults (testPseudonym, 5 s timeouts, no keep-alive).
func defaultTestConfig(upstream string, provider TokenProvider) ProxyConfig {
	return ProxyConfig{
		Upstream:    upstream,
		Provider:    provider,
		Pseudonym:   testPseudonym,
		DialTimeout: 5 * time.Second,
		ReadTimeout: 5 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

// TestComplianceHarnessSmokeTest verifies the test harness end-to-end: a GET
// request flows through ProxyUnderTest to MockUpstreamProxy, the proxy
// injects Proxy-Authorization and Via headers, and the client receives the
// mock response with a Via header.
func TestComplianceHarnessSmokeTest(t *testing.T) {
	const upstreamBody = "hello from upstream"

	upstream := NewMockUpstreamProxy(t, func(_ *http.Request) *http.Response {
		body := upstreamBody
		return &http.Response{
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"X-Upstream": {"true"}},
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
		}
	})
	defer upstream.Close()

	proxy := NewProxyUnderTest(t, upstream.Addr())
	defer proxy.Close()

	// Connect to the proxy and send a GET request in absolute-form.
	conn, err := net.DialTimeout("tcp", proxy.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = conn.Close() }()

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("X-Custom", "value")
	if err := req.WriteProxy(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// -- Assert the client received the expected response --
	assertStatusCode(t, resp, http.StatusOK)
	assertHeaderPresent(t, resp.Header, "X-Upstream", "true")

	// Via header must be present on the response per RFC 9110 §7.6.3.
	if via := resp.Header.Get("Via"); via == "" {
		t.Error("expected Via header in response, got empty")
	} else if !strings.Contains(via, testPseudonym) {
		t.Errorf("Via header %q does not contain pseudonym %q", via, testPseudonym)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != upstreamBody {
		t.Errorf("body: want %q, got %q", upstreamBody, string(body))
	}

	// -- Assert the upstream received the correctly-modified request --
	reqs := upstream.Requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream received %d requests, want 1", len(reqs))
	}
	upstreamReq := reqs[0]

	// Proxy-Authorization must be injected by the proxy.
	assertHeaderPresent(t, upstreamReq.Header, "Proxy-Authorization", "Negotiate test-token")

	// Custom header must be forwarded transparently.
	assertHeaderPresent(t, upstreamReq.Header, "X-Custom", "value")

	// Via must be present on the forwarded request.
	if via := upstreamReq.Header.Get("Via"); via == "" {
		t.Error("expected Via header in upstream request, got empty")
	}

	// Headers that should NOT appear on the forwarded request.
	assertHeaderAbsent(t, upstreamReq.Header, "X-Nonexistent")
}

// ---------------------------------------------------------------------------
// Shared test utilities
// ---------------------------------------------------------------------------

// testPseudonym is a fixed Via pseudonym used across tests for deterministic
// assertions on the Via header value.
const testPseudonym = "spnego-proxy-test"

// stubTokenProvider is a controllable TokenProvider for testing.
type stubTokenProvider struct {
	calls  atomic.Int64
	err    error         // when non-nil, GetToken returns this error
	token  string        // returned on success
	delay  time.Duration // artificial latency before returning
	closed atomic.Bool
}

func (s *stubTokenProvider) GetToken() (string, error) {
	s.calls.Add(1)
	if s.delay > 0 {
		time.Sleep(s.delay)
	}
	if s.err != nil {
		return "", s.err
	}
	return s.token, nil
}

func (s *stubTokenProvider) Close() error {
	s.closed.Store(true)
	return nil
}
