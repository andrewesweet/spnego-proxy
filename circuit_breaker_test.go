package main

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	gobreaker "github.com/sony/gobreaker/v2"
)

// tripBreaker drives cbConsecutiveFailures failures through the provider to
// open the circuit. The inner stub must already have a non-nil err.
func tripBreaker(t *testing.T, cb *CircuitBreakerTokenProvider) {
	t.Helper()
	for i := 0; i < int(cbConsecutiveFailures); i++ {
		_, err := cb.GetToken()
		if err == nil {
			t.Fatalf("expected error on call %d", i+1)
		}
	}
}

func TestCircuitBreakerPassesThrough(t *testing.T) {
	inner := &stubTokenProvider{token: "tok123"}
	cb := NewCircuitBreakerTokenProvider(inner)

	token, err := cb.GetToken()
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

	tripBreaker(t, cb)
	if inner.calls.Load() != int64(cbConsecutiveFailures) {
		t.Fatalf("expected %d inner calls, got %d", cbConsecutiveFailures, inner.calls.Load())
	}

	// Next call should be rejected without calling inner
	callsBefore := inner.calls.Load()
	_, err := cb.GetToken()
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
		_, _ = cb.GetToken()
	}

	// Recover — consecutive counter resets
	inner.err = nil
	token, err := cb.GetToken()
	if err != nil {
		t.Fatalf("unexpected error after recovery: %v", err)
	}
	if token != "tok" {
		t.Errorf("expected tok, got %s", token)
	}

	// Fail again — should still go through (counter was reset)
	inner.err = errors.New("transient again")
	_, err = cb.GetToken()
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
	if !inner.closed.Load() {
		t.Error("expected inner provider to be closed")
	}
}

func TestCircuitBreakerOpenRejectsWithoutCallingInner(t *testing.T) {
	inner := &stubTokenProvider{err: errors.New("fail")}
	cb := NewCircuitBreakerTokenProvider(inner)

	tripBreaker(t, cb)

	// Circuit is now open — verify purely through observable behavior
	callsBefore := inner.calls.Load()
	_, err := cb.GetToken()
	if err == nil {
		t.Fatal("expected error while circuit is open")
	}
	if !strings.Contains(err.Error(), "circuit breaker open") {
		t.Errorf("expected 'circuit breaker open' error, got: %v", err)
	}
	if inner.calls.Load() != callsBefore {
		t.Error("inner provider should not have been called while circuit is open")
	}
}

func TestCircuitBreakerHalfOpenRejectsConcurrentRequests(t *testing.T) {
	// Use a single stub that starts in "fail" mode to trip the breaker, then
	// switches to "slow success" mode for the half-open probe. This avoids
	// directly mutating cb.inner and keeps the test decoupled from field names.
	inner := &stubTokenProvider{
		err:   errors.New("fail"),
		token: "recovered",
		delay: 200 * time.Millisecond,
	}
	cb := newCircuitBreakerTokenProvider(inner, gobreaker.Settings{
		Name:        "test-concurrent",
		MaxRequests: 1,
		Timeout:     50 * time.Millisecond, // fast transition to half-open
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= cbConsecutiveFailures
		},
	})

	tripBreaker(t, cb)

	// Wait for the circuit to transition to half-open
	time.Sleep(100 * time.Millisecond)

	// Switch the stub to succeed slowly so the probe blocks while concurrent
	// callers arrive. No goroutines are running at this point, so the
	// unsynchronised write is safe.
	inner.err = nil

	const concurrency = 5
	errs := make([]error, concurrency)
	tokens := make([]string, concurrency)
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func(idx int) {
			defer wg.Done()
			tokens[idx], errs[idx] = cb.GetToken()
		}(i)
	}
	wg.Wait()

	var successes, tooMany int
	for i := 0; i < concurrency; i++ {
		if errs[i] == nil {
			successes++
			if tokens[i] != "recovered" {
				t.Errorf("expected token 'recovered', got %q", tokens[i])
			}
		} else if strings.Contains(errs[i].Error(), "circuit breaker half-open") {
			tooMany++
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 successful probe, got %d", successes)
	}
	if tooMany != concurrency-1 {
		t.Errorf("expected %d ErrTooManyRequests rejections, got %d", concurrency-1, tooMany)
	}
}
