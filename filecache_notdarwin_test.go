//go:build !darwin

package main

import (
	"strings"
	"testing"
)

func TestFileCacheFlagOnNonDarwin(t *testing.T) {
	_, err := newNativeTokenProvider("proxy:8080", "", true)
	if err == nil {
		t.Fatal("expected error for -file-cache on non-darwin, got nil")
	}
	if !strings.Contains(err.Error(), "macOS") {
		t.Errorf("expected error mentioning macOS, got: %v", err)
	}
}
