package proxy

// authError is a shared base for authentication-related errors. It carries a
// human-readable message and an optional wrapped cause. Embedding authError
// into a concrete error type gives that type Error() and Unwrap() for free.
type authError struct {
	msg   string
	cause error
}

// Error returns the human-readable message for the authentication error.
func (e *authError) Error() string { return e.msg }

// Unwrap returns the wrapped cause, if any, for use with errors.Is/As.
func (e *authError) Unwrap() error { return e.cause }

// CredentialError indicates that token acquisition failed because Kerberos
// credentials are expired, missing, or otherwise unavailable. Callers can
// detect this with errors.As to return a targeted "refresh credentials"
// message. The Unwrap method preserves the original error for debugging.
type CredentialError struct{ authError }

// NegotiationError indicates that SPNEGO/Kerberos negotiation failed after
// credentials were available — typically a misconfigured SPN, unreachable
// KDC, or a token marshalling failure. Callers can detect this with
// errors.As to return a targeted "check configuration" message.
type NegotiationError struct{ authError }
