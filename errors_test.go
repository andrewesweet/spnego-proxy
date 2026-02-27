package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestCredentialErrorMessage(t *testing.T) {
	err := &CredentialError{msg: "could not acquire client credential: KDC_ERR"}
	if got := err.Error(); got != "could not acquire client credential: KDC_ERR" {
		t.Errorf("expected %q, got %q", "could not acquire client credential: KDC_ERR", got)
	}
}

func TestCredentialErrorUnwrap(t *testing.T) {
	inner := errors.New("kdc unreachable")
	err := &CredentialError{msg: "cred fail", cause: inner}
	if unwrapped := errors.Unwrap(err); unwrapped != inner {
		t.Errorf("expected Unwrap to return inner error, got %v", unwrapped)
	}
}

func TestCredentialErrorUnwrapNilCause(t *testing.T) {
	err := &CredentialError{msg: "GSS-API error: no credentials"}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Errorf("expected Unwrap to return nil for nil cause, got %v", unwrapped)
	}
}

func TestCredentialErrorDetectedViaErrorsAs(t *testing.T) {
	inner := errors.New("expired ticket")
	err := &CredentialError{msg: "cred fail", cause: inner}

	var target *CredentialError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *CredentialError")
	}
	if target.msg != "cred fail" {
		t.Errorf("expected msg %q, got %q", "cred fail", target.msg)
	}
}

func TestCredentialErrorDetectedThroughFmtWrap(t *testing.T) {
	inner := &CredentialError{msg: "cred fail", cause: errors.New("kdc")}
	wrapped := fmt.Errorf("provider error: %w", inner)

	var target *CredentialError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should find *CredentialError through fmt.Errorf wrapping")
	}
}

func TestNegotiationErrorMessage(t *testing.T) {
	err := &NegotiationError{msg: "could not initialize context: bad SPN"}
	if got := err.Error(); got != "could not initialize context: bad SPN" {
		t.Errorf("expected %q, got %q", "could not initialize context: bad SPN", got)
	}
}

func TestNegotiationErrorUnwrap(t *testing.T) {
	inner := errors.New("spn mismatch")
	err := &NegotiationError{msg: "neg fail", cause: inner}
	if unwrapped := errors.Unwrap(err); unwrapped != inner {
		t.Errorf("expected Unwrap to return inner error, got %v", unwrapped)
	}
}

func TestNegotiationErrorUnwrapNilCause(t *testing.T) {
	err := &NegotiationError{msg: "GSS-API returned empty token"}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Errorf("expected Unwrap to return nil for nil cause, got %v", unwrapped)
	}
}

func TestNegotiationErrorDetectedViaErrorsAs(t *testing.T) {
	inner := errors.New("marshal failure")
	err := &NegotiationError{msg: "neg fail", cause: inner}

	var target *NegotiationError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *NegotiationError")
	}
	if target.msg != "neg fail" {
		t.Errorf("expected msg %q, got %q", "neg fail", target.msg)
	}
}

func TestNegotiationErrorDetectedThroughFmtWrap(t *testing.T) {
	inner := &NegotiationError{msg: "neg fail", cause: errors.New("ctx")}
	wrapped := fmt.Errorf("provider error: %w", inner)

	var target *NegotiationError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should find *NegotiationError through fmt.Errorf wrapping")
	}
}

func TestCredentialAndNegotiationErrorsAreDistinct(t *testing.T) {
	credErr := &CredentialError{msg: "cred fail"}
	negErr := &NegotiationError{msg: "neg fail"}

	var credTarget *CredentialError
	var negTarget *NegotiationError

	if errors.As(negErr, &credTarget) {
		t.Error("NegotiationError should not match *CredentialError")
	}
	if errors.As(credErr, &negTarget) {
		t.Error("CredentialError should not match *NegotiationError")
	}
}
