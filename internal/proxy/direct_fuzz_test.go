package proxy

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
// the request-smuggling vector in handleDirectHTTP — is caught.
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

// wellFormedHost reports whether h is a realistic authority: a valid IP literal
// (optionally bracketed) or a clean DNS-charset name, optionally with a port.
// The differential below is only sound for such inputs. On malformed bracketing
// (e.g. "[z:" vs "[[z:]") production's balanced stripIPv6Brackets and
// sameHostRef's independent TrimPrefix/TrimSuffix legitimately diverge without
// any two genuinely valid hosts colliding, so asserting there is noise, not a
// smuggling vector. Mirrors differentiableHost in noproxy_fuzz_test.go.
func wellFormedHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		host = h
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	}
	if _, e := netip.ParseAddr(host); e == nil {
		return true
	}
	if host == "" {
		return false
	}
	for i := range len(host) {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

// FuzzSameHost guards the keep-alive connection binding in handleDirectHTTP:
// sameHost falsely reporting two different hosts as equal lets a smuggled
// pipelined request ride a direct connection bound to a different,
// unauthorised host (the keep-alive binding in handleDirectHTTP).
//
// Assertions:
//   - never panics;
//   - reflexivity: sameHost(a,a,d) is always true;
//   - symmetry: sameHost(a,b,d) == sameHost(b,a,d);
//   - one-directional soundness: for well-formed authorities,
//     sameHost(a,b,d)==true implies an independent canonicalisation also
//     considers them equal. The converse is NOT asserted (production being
//     stricter than the reference is safe), and malformed-bracket inputs are
//     excluded via wellFormedHost (the two bracket-stripping strategies diverge
//     there without any valid hosts colliding — noise, not a smuggling vector).
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
		// Sound differential, restricted to well-formed authorities: only there
		// do production's canon and sameHostRef agree on bracket handling, so a
		// disagreement is a real collision rather than malformed-bracket noise.
		if ab && wellFormedHost(a) && wellFormedHost(b) &&
			sameHostRef(a, defaultPort) != sameHostRef(b, defaultPort) {
			t.Fatalf("sameHost equated different hosts (smuggling vector): a=%q b=%q d=%q ref(a)=%q ref(b)=%q",
				a, b, defaultPort, sameHostRef(a, defaultPort), sameHostRef(b, defaultPort))
		}
	})
}
