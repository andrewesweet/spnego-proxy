package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
)

// extractHost returns the host portion of addr, stripping any port suffix.
// If addr has no port, it is returned unchanged.
func extractHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// UpstreamTLSConfig holds optional TLS settings for the upstream proxy connection.
type UpstreamTLSConfig struct {
	Enabled            bool
	CAFile             string
	InsecureSkipVerify bool
	// TLSConfig is the pre-built *tls.Config constructed once at startup.
	// dialUpstream clones it and sets ServerName per connection.
	// Call buildTLSConfig to populate it from the other fields.
	TLSConfig *tls.Config
	// Dialer is the pre-allocated net.Dialer constructed once at startup.
	Dialer *net.Dialer
}

// buildTLSConfig constructs a *tls.Config from the fields of UpstreamTLSConfig
// and stores it in TLSConfig. It is called once at startup (and in tests) so
// that dialUpstream can clone the result without re-reading the CA file per connection.
func (c *UpstreamTLSConfig) buildTLSConfig() error {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		caCert, err := os.ReadFile(c.CAFile)
		if err != nil {
			return fmt.Errorf("failed to read upstream CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return fmt.Errorf("failed to parse upstream CA certificate from %s", c.CAFile)
		}
		tc.RootCAs = pool
	}
	if c.InsecureSkipVerify {
		tc.InsecureSkipVerify = true //nolint:gosec // user explicitly opted in via -upstream-tls-insecure
	}
	c.TLSConfig = tc
	return nil
}

// dialUpstream connects to the upstream proxy, optionally using TLS.
// tlsCfg.Dialer must be non-nil; it is pre-allocated at startup by main().
func dialUpstream(addr string, tlsCfg UpstreamTLSConfig) (net.Conn, error) {
	dialer := tlsCfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	if !tlsCfg.Enabled {
		return dialer.Dial("tcp", addr)
	}

	var tc *tls.Config
	if tlsCfg.TLSConfig != nil {
		tc = tlsCfg.TLSConfig.Clone()
	} else {
		tc = &tls.Config{MinVersion: tls.VersionTLS12} //nolint:gosec // fallback for tests without pre-built config
	}
	tc.ServerName = extractHost(addr)

	return tls.DialWithDialer(dialer, "tcp", addr, tc)
}
