package main

import (
	"errors"
	"fmt"
	"testing"
)

func TestAuthErrors(t *testing.T) {
	type errorCase struct {
		name        string
		constructor func(msg string, cause error) error
		asTarget    func() (any, func() string) // returns (&target, func() string { return target.msg })
	}

	cases := []errorCase{
		{
			name: "CredentialError",
			constructor: func(msg string, cause error) error {
				return &CredentialError{authError{msg: msg, cause: cause}}
			},
			asTarget: func() (any, func() string) {
				var t *CredentialError
				return &t, func() string { return t.msg }
			},
		},
		{
			name: "NegotiationError",
			constructor: func(msg string, cause error) error {
				return &NegotiationError{authError{msg: msg, cause: cause}}
			},
			asTarget: func() (any, func() string) {
				var t *NegotiationError
				return &t, func() string { return t.msg }
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("message", func(t *testing.T) {
				err := tc.constructor("sentinel message text", nil)
				if got := err.Error(); got != "sentinel message text" {
					t.Errorf("expected %q, got %q", "sentinel message text", got)
				}
			})

			t.Run("unwrap", func(t *testing.T) {
				inner := errors.New("inner cause")
				err := tc.constructor("outer msg", inner)
				if !errors.Is(err, inner) {
					t.Error("expected errors.Is to find inner error through Unwrap")
				}
			})

			t.Run("unwrapNil", func(t *testing.T) {
				err := tc.constructor("no cause msg", nil)
				if unwrapped := errors.Unwrap(err); unwrapped != nil {
					t.Errorf("expected Unwrap to return nil for nil cause, got %v", unwrapped)
				}
			})

			t.Run("errorsAs", func(t *testing.T) {
				inner := errors.New("some inner")
				err := tc.constructor("as msg", inner)
				target, getMsg := tc.asTarget()
				if !errors.As(err, target) {
					t.Fatalf("errors.As should match %s", tc.name)
				}
				if got := getMsg(); got != "as msg" {
					t.Errorf("expected msg %q, got %q", "as msg", got)
				}
			})

			t.Run("fmtWrap", func(t *testing.T) {
				inner := tc.constructor("inner msg", errors.New("root"))
				wrapped := fmt.Errorf("provider error: %w", inner)
				target, _ := tc.asTarget()
				if !errors.As(wrapped, target) {
					t.Fatalf("errors.As should find %s through fmt.Errorf wrapping", tc.name)
				}
			})
		})
	}

	t.Run("distinct", func(t *testing.T) {
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
	})
}
