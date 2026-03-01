package main

import (
	"net"
	"net/http"
	"testing"
)

func TestParseAllowedIPs(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"empty allows all", "", 0, false},
		{"single IP", "192.168.1.1", 1, false},
		{"multiple IPs", "192.168.1.1,10.0.0.1", 2, false},
		{"CIDR notation", "192.168.1.0/24", 1, false},
		{"mixed IPs and CIDRs", "192.168.1.1,10.0.0.0/8", 2, false},
		{"invalid input", "not-an-ip", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseAllowList(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != tc.wantLen {
				t.Errorf("want %d entries, got %d", tc.wantLen, len(result))
			}
		})
	}
}

func TestIPAllowed(t *testing.T) {
	allowList, err := parseAllowList("192.168.1.0/24,10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.5", true},
		{"192.168.1.255", true},
		{"192.168.2.1", false},
		{"10.0.0.1", true},
		{"10.0.0.2", false},
	}
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			if got := ipAllowed(net.ParseIP(tc.ip), allowList); got != tc.want {
				t.Errorf("ipAllowed(%s): want %v, got %v", tc.ip, tc.want, got)
			}
		})
	}
}

func TestIPAllowedEmptyList(t *testing.T) {
	if !ipAllowed(net.ParseIP("1.2.3.4"), nil) {
		t.Error("empty allowlist should allow all IPs")
	}
}

func TestAllowlistRejectsUnlisted(t *testing.T) {
	raw := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp, _ := proxyRawRoundTrip(t, raw, func(p *ProxyUnderTest) {
		// Test client connects from 127.0.0.1. Allow only 10.0.0.1.
		list, _ := parseAllowList("10.0.0.1")
		p.SetAllowedIPs(list)
	})
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusForbidden)
}

func TestAllowlistAllowsLocalhost(t *testing.T) {
	raw := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resp, _ := proxyRawRoundTrip(t, raw, func(p *ProxyUnderTest) {
		list, _ := parseAllowList("127.0.0.1")
		p.SetAllowedIPs(list)
	})
	defer func() { _ = resp.Body.Close() }()
	assertStatusCode(t, resp, http.StatusOK)
}
