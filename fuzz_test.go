package main

import (
	"strings"
	"testing"
)

func FuzzSplitCSV(f *testing.F) {
	f.Add("443")
	f.Add("443,8080")
	f.Add("443, 8080, 9090")
	f.Add("")
	f.Add(",,,")
	f.Add(" , , ")
	f.Add("*")
	f.Add("443,*,8080")
	f.Add("  443  ")

	f.Fuzz(func(t *testing.T, s string) {
		result := splitCSV(s)

		// Invariant 1: no empty tokens in result.
		for i, token := range result {
			if token == "" {
				t.Errorf("splitCSV(%q): token %d is empty", s, i)
			}
		}

		// Invariant 2: no leading/trailing whitespace in tokens.
		for i, token := range result {
			if token != strings.TrimSpace(token) {
				t.Errorf("splitCSV(%q): token %d has whitespace: %q", s, i, token)
			}
		}

		// Invariant 3: all tokens must be substrings of the input.
		for i, token := range result {
			if !strings.Contains(s, token) {
				t.Errorf("splitCSV(%q): token %d = %q not found in input", s, i, token)
			}
		}
	})
}

func FuzzConnectPortAllowed(f *testing.F) {
	f.Add("443", "443,8080")
	f.Add("80", "443,8080")
	f.Add("443", "")
	f.Add("443", "*")
	f.Add("", "443")
	f.Add("9999", "443,8080,9090")

	f.Fuzz(func(t *testing.T, port, allowedCSV string) {
		allowed := splitCSV(allowedCSV)
		result := connectPortAllowed(port, allowed)

		// Invariant 1: empty allowed list always returns true.
		if len(allowed) == 0 && !result {
			t.Errorf("connectPortAllowed(%q, []) = false, want true", port)
		}

		// Invariant 2: wildcard always allows.
		for _, p := range allowed {
			if p == "*" && !result {
				t.Errorf("connectPortAllowed(%q, %v) = false with wildcard present", port, allowed)
			}
		}

		// Invariant 3: if port is in the allowed list, result must be true.
		for _, p := range allowed {
			if p == port && !result {
				t.Errorf("connectPortAllowed(%q, %v) = false but port is in list", port, allowed)
			}
		}

		// Invariant 4: if port is NOT in the list and no wildcard, result must be false.
		if len(allowed) > 0 {
			hasWildcard := false
			inList := false
			for _, p := range allowed {
				if p == "*" {
					hasWildcard = true
				}
				if p == port {
					inList = true
				}
			}
			if !hasWildcard && !inList && result {
				t.Errorf("connectPortAllowed(%q, %v) = true, want false (port not in list, no wildcard)", port, allowed)
			}
		}
	})
}
