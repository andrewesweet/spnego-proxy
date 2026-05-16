package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"
)

// sameHostRef is an independent canonicalisation used only to bound sameHost's
// true-decisions. It deliberately differs from production (independent bracket
// stripping; explicit netip normalisation of IP literals) so a collision bug
// in production's canon — two genuinely different hosts treated as the same,
// the response/request-smuggling vector at direct.go:104-110 — is caught.
func sameHostRef(h, defaultPort string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		host = h
		port = defaultPort
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
	}
	if a, e := netip.ParseAddr(host); e == nil {
		host = a.String()
	}
	return host + "|" + port
}

// FuzzSameHost guards the keep-alive connection binding in handleDirectHTTP:
// sameHost falsely reporting two different hosts as equal lets a smuggled
// pipelined request ride a direct connection bound to a different,
// unauthorised host (direct.go:104-110).
//
// Assertions:
//   - never panics;
//   - reflexivity: sameHost(a,a,d) is always true;
//   - symmetry: sameHost(a,b,d) == sameHost(b,a,d);
//   - one-directional soundness: sameHost(a,b,d)==true implies an independent
//     canonicalisation also considers them equal. The converse is NOT asserted
//     (production being stricter than the reference is safe).
func FuzzSameHost(f *testing.F) {
	f.Add("Example.com:80", "example.com", "80")
	f.Add("[::1]", "[0:0:0:0:0:0:0:1]:80", "80")
	f.Add("[::1]:80", "[::1]:80", "80")
	f.Add("host", "host:80", "80")
	f.Add(" host ", "host", "80")
	f.Add("[::ffff:1.2.3.4]", "1.2.3.4", "443")
	f.Add("h:80", "h:0080", "80")
	f.Add("[bad", "[bad", "80")
	f.Add("a:b:c", "a:b:c", "443")

	f.Fuzz(func(t *testing.T, a, b, defaultPort string) {
		if !sameHost(a, a, defaultPort) {
			t.Fatalf("reflexivity violated: sameHost(%q,%q,%q)=false", a, a, defaultPort)
		}
		ab := sameHost(a, b, defaultPort)
		if ab != sameHost(b, a, defaultPort) {
			t.Fatalf("symmetry violated: a=%q b=%q d=%q", a, b, defaultPort)
		}
		if ab && sameHostRef(a, defaultPort) != sameHostRef(b, defaultPort) {
			t.Fatalf("sameHost equated different hosts (smuggling vector): a=%q b=%q d=%q ref(a)=%q ref(b)=%q",
				a, b, defaultPort, sameHostRef(a, defaultPort), sameHostRef(b, defaultPort))
		}
	})
}
