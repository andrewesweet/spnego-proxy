package main

// CredentialError indicates that token acquisition failed because Kerberos
// credentials are expired, missing, or otherwise unavailable. Callers can
// detect this with errors.As to return a targeted "refresh credentials"
// message. The Unwrap method preserves the original error for debugging.
type CredentialError struct {
	msg   string
	cause error
}

func (e *CredentialError) Error() string { return e.msg }
func (e *CredentialError) Unwrap() error { return e.cause }

// NegotiationError indicates that SPNEGO/Kerberos negotiation failed after
// credentials were available — typically a misconfigured SPN, unreachable
// KDC, or a token marshalling failure. Callers can detect this with
// errors.As to return a targeted "check configuration" message.
type NegotiationError struct {
	msg   string
	cause error
}

func (e *NegotiationError) Error() string { return e.msg }
func (e *NegotiationError) Unwrap() error { return e.cause }
