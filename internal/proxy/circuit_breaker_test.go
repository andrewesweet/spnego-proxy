package proxy

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gobreaker "github.com/sony/gobreaker/v2"
)

// tripBreaker drives cbConsecutiveFailures failures through the provider to
// open the circuit. The inner stub must already have a non-nil err.
func tripBreaker(t *testing.T, cb *CircuitBreakerTokenProvider) {
	t.Helper()
	for i := range int(CBConsecutiveFailures) {
		_, err := cb.GetToken()
		if err == nil {
			t.Fatalf("expected error on call %d", i+1)
		}
	}
}

func TestCircuitBreakerPassesThrough(t *testing.T) {
	inner := &stubTokenProvider{token: "tok123"}
	cb := NewCircuitBreakerTokenProvider(inner, CBConsecutiveFailures, CBTimeout)

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
	cb := NewCircuitBreakerTokenProvider(inner, CBConsecutiveFailures, CBTimeout)

	tripBreaker(t, cb)
	if inner.calls.Load() != int64(CBConsecutiveFailures) {
		t.Fatalf("expected %d inner calls, got %d", CBConsecutiveFailures, inner.calls.Load())
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
	cb := NewCircuitBreakerTokenProvider(inner, CBConsecutiveFailures, CBTimeout)

	// Fail twice (below threshold), then succeed
	inner.err = errors.New("transient")
	for range int(CBConsecutiveFailures) - 1 {
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
	cb := NewCircuitBreakerTokenProvider(inner, CBConsecutiveFailures, CBTimeout)

	if err := cb.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !inner.closed.Load() {
		t.Error("expected inner provider to be closed")
	}
}

func TestCircuitBreakerOpenRejectsWithoutCallingInner(t *testing.T) {
	inner := &stubTokenProvider{err: errors.New("fail")}
	cb := NewCircuitBreakerTokenProvider(inner, CBConsecutiveFailures, CBTimeout)

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

// TestCircuitBreakerSerialisesConcurrentCallersWhileClosed pins the guarantee
// the breaker exists for: while the circuit is Closed, a burst of callers must
// not each reach the credential backend. gobreaker admits every caller in the
// Closed state and only records a result afterwards, so without serialisation
// a burst of N callers sends N failed logins even when the threshold is far
// smaller than N.
func TestCircuitBreakerSerialisesConcurrentCallersWhileClosed(t *testing.T) {
	const concurrency = 10
	inner := &stubTokenProvider{
		err:   errors.New("KDC rejected pre-authentication"),
		delay: 20 * time.Millisecond,
	}
	cb := NewCircuitBreakerTokenProvider(inner, CBConsecutiveFailures, CBTimeout)

	var wg sync.WaitGroup
	start := make(chan struct{})
	var rejected atomic.Int64
	for range concurrency {
		wg.Go(func() {
			<-start
			_, err := cb.GetToken()
			var cbErr *CircuitBreakerError
			if errors.As(err, &cbErr) {
				rejected.Add(1)
			}
		})
	}
	close(start)
	wg.Wait()

	if got := inner.calls.Load(); got != int64(CBConsecutiveFailures) {
		t.Errorf("credential backend saw %d login attempts, want %d (the breaker threshold)", got, CBConsecutiveFailures)
	}
	if got := rejected.Load(); got != concurrency-CBConsecutiveFailures {
		t.Errorf("breaker rejected %d of %d callers, want %d", got, concurrency, concurrency-CBConsecutiveFailures)
	}
}

func TestCircuitBreakerSerialisesConcurrentCallersWhileHalfOpen(t *testing.T) {
	// Use a single stub that starts in "fail" mode to trip the breaker, then
	// switches to "slow success" mode for the half-open probe. This avoids
	// directly mutating cb.inner and keeps the test decoupled from field names.
	inner := &stubTokenProvider{
		err:   errors.New("fail"),
		token: "recovered",
		delay: 100 * time.Millisecond,
	}
	cb := newCircuitBreakerTokenProvider(inner, gobreaker.Settings{
		Name:        "test-concurrent",
		MaxRequests: 1,
		Timeout:     50 * time.Millisecond, // fast transition to half-open
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= CBConsecutiveFailures
		},
	}, CBConsecutiveFailures)

	tripBreaker(t, cb)

	// Poll until the circuit transitions to half-open instead of using a
	// fixed sleep, which is fragile on slow or overloaded CI systems.
	deadline := time.After(2 * time.Second)
	for cb.cb.State() != gobreaker.StateHalfOpen {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for circuit breaker to transition to half-open")
		case <-time.After(1 * time.Millisecond):
		}
	}

	// Switch the stub to succeed slowly so the probe blocks while concurrent
	// callers arrive. No goroutines are running at this point, so the
	// unsynchronised write is safe.
	inner.err = nil

	const concurrency = 5
	errs := make([]error, concurrency)
	tokens := make([]string, concurrency)
	var wg sync.WaitGroup
	for i := range concurrency {
		wg.Go(func() {
			tokens[i], errs[i] = cb.GetToken()
		})
	}
	wg.Wait()

	// Callers that arrive while a probe is in flight queue behind it instead
	// of being rejected, so every caller gets a token.
	for i := range concurrency {
		if errs[i] != nil {
			t.Errorf("caller %d was rejected while a probe was in flight: %v", i, errs[i])
			continue
		}
		if tokens[i] != "recovered" {
			t.Errorf("expected token 'recovered', got %q", tokens[i])
		}
	}
	// Serialisation is the property that bounds failed logins: the credential
	// backend never runs two acquisitions at once.
	if got := inner.maxInFlight.Load(); got != 1 {
		t.Errorf("credential backend ran %d acquisitions at once, want 1", got)
	}
}
