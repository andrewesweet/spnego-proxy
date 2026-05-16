package proxy

import "testing"

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
