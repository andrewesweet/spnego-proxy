package main

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	gobreaker "github.com/sony/gobreaker/v2"
)

// Default circuit breaker settings.
const (
	// cbConsecutiveFailures is the number of consecutive GetToken failures
	// before the circuit opens. Three failures avoids tripping on a single
	// transient error while still reacting quickly to broken credentials.
	cbConsecutiveFailures = 3

	// cbTimeout is how long the circuit stays open before allowing a single
	// probe request (half-open state). 30 seconds gives the operator time
	// to notice logs and act (e.g. kinit) without holding the circuit open
	// so long that recovery is delayed.
	cbTimeout = 30 * time.Second
)

// CircuitBreakerTokenProvider wraps a TokenProvider with a circuit breaker
// that prevents repeated calls to a failing credential backend. This avoids
// account lockout from rapid authentication failures (e.g. stale Kerberos
// tickets triggering KDC password-attempt counters).
type CircuitBreakerTokenProvider struct {
	inner TokenProvider
	cb    *gobreaker.CircuitBreaker[string]
}

// NewCircuitBreakerTokenProvider wraps the given TokenProvider with a circuit
// breaker. When cbConsecutiveFailures consecutive GetToken calls fail, the
// circuit opens and immediately rejects further attempts for cbTimeout. After
// the timeout, a single probe request is allowed through (half-open); if it
// succeeds the circuit closes, otherwise it reopens.
func NewCircuitBreakerTokenProvider(inner TokenProvider) *CircuitBreakerTokenProvider {
	return newCircuitBreakerTokenProvider(inner, gobreaker.Settings{
		Name:        "spnego-token",
		MaxRequests: 1,
		Timeout:     cbTimeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= cbConsecutiveFailures
		},
		OnStateChange: func(name string, from gobreaker.State, to gobreaker.State) {
			slog.Warn("circuit breaker state change", "name", name, "from", from.String(), "to", to.String())
		},
	})
}

// newCircuitBreakerTokenProvider is the internal constructor that accepts
// explicit gobreaker.Settings, used by tests to override timeouts.
func newCircuitBreakerTokenProvider(inner TokenProvider, settings gobreaker.Settings) *CircuitBreakerTokenProvider {
	cb := gobreaker.NewCircuitBreaker[string](settings)
	return &CircuitBreakerTokenProvider{inner: inner, cb: cb}
}

// GetToken acquires a token from the wrapped provider, subject to circuit
// breaker policy. Returns a descriptive error when the circuit is open.
func (p *CircuitBreakerTokenProvider) GetToken() (string, error) {
	token, err := p.cb.Execute(func() (string, error) {
		return p.inner.GetToken()
	})
	if err != nil {
		if errors.Is(err, gobreaker.ErrOpenState) {
			return "", fmt.Errorf("circuit breaker open: token acquisition disabled after %d consecutive failures", cbConsecutiveFailures)
		}
		if errors.Is(err, gobreaker.ErrTooManyRequests) {
			return "", fmt.Errorf("circuit breaker half-open: probe in progress, rejecting concurrent request")
		}
		return "", err
	}
	return token, nil
}

// Close delegates to the wrapped provider.
func (p *CircuitBreakerTokenProvider) Close() error {
	return p.inner.Close()
}
