package main

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	gobreaker "github.com/sony/gobreaker/v2"
)

// stubTokenProvider is a controllable TokenProvider for testing.
type stubTokenProvider struct {
	calls  atomic.Int64
	err    error  // when non-nil, GetToken returns this error
	token  string // returned on success
	closed bool
}

func (s *stubTokenProvider) GetToken(_ string) (string, error) {
	s.calls.Add(1)
	if s.err != nil {
		return "", s.err
	}
	return s.token, nil
}

func (s *stubTokenProvider) Close() error {
	s.closed = true
	return nil
}

func TestCircuitBreakerPassesThrough(t *testing.T) {
	inner := &stubTokenProvider{token: "tok123"}
	cb := NewCircuitBreakerTokenProvider(inner)

	token, err := cb.GetToken("proxy:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "tok123" {
		t.Errorf("expected tok123, got %s", token)
	}
	if inner.calls.Load() != 1 {
		t.Errorf("expected 1 call, got %d", inner.calls.Load())
	}
}

func TestCircuitBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	inner := &stubTokenProvider{err: errors.New("kdc error")}
	cb := NewCircuitBreakerTokenProvider(inner)

	// First cbConsecutiveFailures calls go through to inner
	for i := 0; i < int(cbConsecutiveFailures); i++ {
		_, err := cb.GetToken("proxy:8080")
		if err == nil {
			t.Fatalf("expected error on call %d", i+1)
		}
	}
	if inner.calls.Load() != int64(cbConsecutiveFailures) {
		t.Fatalf("expected %d inner calls, got %d", cbConsecutiveFailures, inner.calls.Load())
	}

	// Next call should be rejected without calling inner
	callsBefore := inner.calls.Load()
	_, err := cb.GetToken("proxy:8080")
	if err == nil {
		t.Fatal("expected circuit breaker error")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected 'circuit breaker open' error, got: %v", err)
	}
	if inner.calls.Load() != callsBefore {
		t.Error("inner provider should not have been called while circuit is open")
	}
}

func TestCircuitBreakerDoesNotTripOnIntermittentFailures(t *testing.T) {
	inner := &stubTokenProvider{token: "tok"}
	cb := NewCircuitBreakerTokenProvider(inner)

	// Fail twice (below threshold), then succeed
	inner.err = errors.New("transient")
	for i := 0; i < int(cbConsecutiveFailures)-1; i++ {
		_, _ = cb.GetToken("proxy:8080")
	}

	// Recover — consecutive counter resets
	inner.err = nil
	token, err := cb.GetToken("proxy:8080")
	if err != nil {
		t.Fatalf("unexpected error after recovery: %v", err)
	}
	if token != "tok" {
		t.Errorf("expected tok, got %s", token)
	}

	// Fail again — should still go through (counter was reset)
	inner.err = errors.New("transient again")
	_, err = cb.GetToken("proxy:8080")
	if err == nil {
		t.Fatal("expected error")
	}
	// Should be the inner error, not a circuit breaker error
	if strings.Contains(err.Error(), "circuit breaker") {
		t.Errorf("circuit should not have tripped, got: %v", err)
	}
}

func TestCircuitBreakerClosesDelegatesToInner(t *testing.T) {
	inner := &stubTokenProvider{token: "tok"}
	cb := NewCircuitBreakerTokenProvider(inner)

	if err := cb.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !inner.closed {
		t.Error("expected inner provider to be closed")
	}
}

func TestCircuitBreakerReportsState(t *testing.T) {
	inner := &stubTokenProvider{err: errors.New("fail")}
	cb := NewCircuitBreakerTokenProvider(inner)

	if cb.cb.State() != gobreaker.StateClosed {
		t.Fatalf("expected closed state initially")
	}

	// Trip the breaker
	for i := 0; i < int(cbConsecutiveFailures); i++ {
		_, _ = cb.GetToken("proxy:8080")
	}

	if cb.cb.State() != gobreaker.StateOpen {
		t.Errorf("expected open state after %d failures, got %s", cbConsecutiveFailures, cb.cb.State())
	}
}
