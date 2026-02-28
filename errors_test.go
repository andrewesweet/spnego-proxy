package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestCredentialErrorMessage(t *testing.T) {
	err := &CredentialError{authError{msg: "could not acquire client credential: KDC_ERR"}}
	if got := err.Error(); got != "could not acquire client credential: KDC_ERR" {
		t.Errorf("expected %q, got %q", "could not acquire client credential: KDC_ERR", got)
	}
}

func TestCredentialErrorUnwrap(t *testing.T) {
	inner := errors.New("kdc unreachable")
	err := &CredentialError{authError{msg: "cred fail", cause: inner}}
	if !errors.Is(err, inner) {
		t.Errorf("expected errors.Is to find inner error through Unwrap")
	}
}

func TestCredentialErrorUnwrapNilCause(t *testing.T) {
	err := &CredentialError{authError{msg: "GSS-API error: no credentials"}}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Errorf("expected Unwrap to return nil for nil cause, got %v", unwrapped)
	}
}

func TestCredentialErrorDetectedViaErrorsAs(t *testing.T) {
	inner := errors.New("expired ticket")
	err := &CredentialError{authError{msg: "cred fail", cause: inner}}

	var target *CredentialError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *CredentialError")
	}
	if target.msg != "cred fail" {
		t.Errorf("expected msg %q, got %q", "cred fail", target.msg)
	}
}

func TestCredentialErrorDetectedThroughFmtWrap(t *testing.T) {
	inner := &CredentialError{authError{msg: "cred fail", cause: errors.New("kdc")}}
	wrapped := fmt.Errorf("provider error: %w", inner)

	var target *CredentialError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should find *CredentialError through fmt.Errorf wrapping")
	}
}

func TestNegotiationErrorMessage(t *testing.T) {
	err := &NegotiationError{authError{msg: "could not initialize context: bad SPN"}}
	if got := err.Error(); got != "could not initialize context: bad SPN" {
		t.Errorf("expected %q, got %q", "could not initialize context: bad SPN", got)
	}
}

func TestNegotiationErrorUnwrap(t *testing.T) {
	inner := errors.New("spn mismatch")
	err := &NegotiationError{authError{msg: "neg fail", cause: inner}}
	if !errors.Is(err, inner) {
		t.Errorf("expected errors.Is to find inner error through Unwrap")
	}
}

func TestNegotiationErrorUnwrapNilCause(t *testing.T) {
	err := &NegotiationError{authError{msg: "GSS-API returned empty token"}}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Errorf("expected Unwrap to return nil for nil cause, got %v", unwrapped)
	}
}

func TestNegotiationErrorDetectedViaErrorsAs(t *testing.T) {
	inner := errors.New("marshal failure")
	err := &NegotiationError{authError{msg: "neg fail", cause: inner}}

	var target *NegotiationError
	if !errors.As(err, &target) {
		t.Fatal("errors.As should match *NegotiationError")
	}
	if target.msg != "neg fail" {
		t.Errorf("expected msg %q, got %q", "neg fail", target.msg)
	}
}

func TestNegotiationErrorDetectedThroughFmtWrap(t *testing.T) {
	inner := &NegotiationError{authError{msg: "neg fail", cause: errors.New("ctx")}}
	wrapped := fmt.Errorf("provider error: %w", inner)

	var target *NegotiationError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As should find *NegotiationError through fmt.Errorf wrapping")
	}
}

func TestCredentialAndNegotiationErrorsAreDistinct(t *testing.T) {
	credErr := &CredentialError{authError{msg: "cred fail"}}
	negErr := &NegotiationError{authError{msg: "neg fail"}}

	var credTarget *CredentialError
	var negTarget *NegotiationError

	if errors.As(negErr, &credTarget) {
		t.Error("NegotiationError should not match *CredentialError")
	}
	if errors.As(credErr, &negTarget) {
		t.Error("CredentialError should not match *NegotiationError")
	}
}
