package main

import (
	"testing"
	"unicode/utf8"
)

func TestNormalizeSPN(t *testing.T) {
	tests := []struct {
		name         string
		spn          string
		targetSep    byte
		alternateSep byte
		want         string
	}{
		// GSS-API target separator is '@'
		{"gss: already correct format", "HTTP@host.example.com", '@', '/', "HTTP@host.example.com"},
		{"gss: convert from krb5 format", "HTTP/host.example.com", '@', '/', "HTTP@host.example.com"},
		{"gss: no recognized separator", "host.example.com", '@', '/', "host.example.com"},

		// gokrb5 target separator is '/'
		{"krb5: already correct format", "HTTP/host.example.com", '/', '@', "HTTP/host.example.com"},
		{"krb5: convert from gss format", "HTTP@host.example.com", '/', '@', "HTTP/host.example.com"},
		{"krb5: no recognized separator", "host.example.com", '/', '@', "host.example.com"},

		// Both separators present — target found, return as-is
		{"both seps: target found first", "HTTP/host@REALM", '/', '@', "HTTP/host@REALM"},
		{"both seps: target found first gss", "HTTP@host/path", '@', '/', "HTTP@host/path"},

		// Non-HTTP service types
		{"gss: custom service type", "CIFS/fileserver.example.com", '@', '/', "CIFS@fileserver.example.com"},
		{"krb5: custom service type", "CIFS@fileserver.example.com", '/', '@', "CIFS/fileserver.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSPN(tt.spn, tt.targetSep, tt.alternateSep)
			if got != tt.want {
				t.Errorf("normalizeSPN(%q, %q, %q) = %q, want %q",
					tt.spn, string(tt.targetSep), string(tt.alternateSep), got, tt.want)
			}
		})
	}
}

func FuzzNormalizeSPN(f *testing.F) {
	// Seed corpus from the table-driven test.
	f.Add("HTTP@host.example.com", byte('@'), byte('/'))
	f.Add("HTTP/host.example.com", byte('@'), byte('/'))
	f.Add("host.example.com", byte('@'), byte('/'))
	f.Add("HTTP/host@REALM", byte('/'), byte('@'))
	f.Add("CIFS/fileserver.example.com", byte('@'), byte('/'))
	f.Add("", byte('@'), byte('/'))

	f.Fuzz(func(t *testing.T, spn string, targetSep, alternateSep byte) {
		if !utf8.ValidString(spn) {
			t.Skip("invalid UTF-8")
		}
		// In practice only ASCII separators are used ('@', '/').
		// Non-ASCII bytes produce multi-byte UTF-8 via string(byte),
		// which changes length — skip them for the length invariant.
		if targetSep > 127 || alternateSep > 127 {
			t.Skip("non-ASCII separators not used in practice")
		}
		result := normalizeSPN(spn, targetSep, alternateSep)

		// Invariant 1: result length should be the same as input length
		// (holds when both separators are ASCII).
		if len(result) != len(spn) {
			t.Errorf("normalizeSPN(%q, %q, %q) changed length: %d → %d",
				spn, string(targetSep), string(alternateSep), len(spn), len(result))
		}

		// Invariant 2: result must be valid UTF-8 if input was.
		if !utf8.ValidString(result) {
			t.Errorf("normalizeSPN(%q, %q, %q) produced invalid UTF-8: %q",
				spn, string(targetSep), string(alternateSep), result)
		}

		// Invariant 3: must not panic (implicit).
	})
}

func FuzzExtractHost(f *testing.F) {
	f.Add("proxy.example.com:8080")
	f.Add("proxy.example.com")
	f.Add("[::1]:443")
	f.Add("[::1]")
	f.Add("127.0.0.1:80")
	f.Add("")
	f.Add(":443")
	f.Add("host:")

	f.Fuzz(func(t *testing.T, addr string) {
		result := extractHost(addr)

		// Invariant 1: result must not be longer than input.
		if len(result) > len(addr) {
			t.Errorf("extractHost(%q) = %q (longer than input)", addr, result)
		}

		// Invariant 2: must not panic (implicit).
	})
}
