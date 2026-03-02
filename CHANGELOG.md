# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.1.0] - 2026-03-02


### Added
- Add logging for TE/CL conflict resolution and configurable circuit breaker
- Add idle timeout for CONNECT tunnels
- Add optional IP allowlist for client access control
- Add optional TLS support for upstream proxy connection
- Add -version flag with build-time version embedding

### Fixed
- Add dial and read timeouts to prevent goroutine/FD leaks
- Satisfy errcheck linter in main_test.go
- Address issues #28-35 and #38 — eight bug fixes and improvements
- Address lint issues from CI
- Address gofmt and revive lint issues

### Security
- Fatal exit on crypto/rand failure instead of timestamp fallback
- Default -connect-ports to 443 instead of allowing all ports
- Return 502 instead of raw relay when upstream response is unparseable
- Zero password bytes after Kerberos client initialization
[0.1.0]: https://github.com/andrewesweet/spnego-proxy/releases/tag/0.1.0

