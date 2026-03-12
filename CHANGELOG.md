# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [1.1.1] - 2026-03-12


### Fixed
- Use cross-compilation for linux/arm64 release build

## [1.1.0] - 2026-03-11


### Added
- Add Dockerfile for minimal container image

## [1.0.0] - 2026-03-10


### Added
- Add logging for TE/CL conflict resolution and configurable circuit breaker
- Add idle timeout for CONNECT tunnels
- Add optional IP allowlist for client access control
- Add optional TLS support for upstream proxy connection
- Add -version flag with build-time version embedding
- Add NoProxyMatcher and resolveNoProxy for bypass pattern matching
- Add noproxy bypass in handleClient with direct HTTP and CONNECT paths
- Support bare * wildcard in noproxy patterns
- Add NoProxyMatcher and resolveNoProxy for bypass pattern matching
- Add noproxy bypass in handleClient with direct HTTP and CONNECT paths
- Support bare * wildcard in noproxy patterns

### Fixed
- Add dial and read timeouts to prevent goroutine/FD leaks
- Satisfy errcheck linter in main_test.go
- Address issues #28-35 and #38 — eight bug fixes and improvements
- Address lint issues from CI
- Address gofmt and revive lint issues
- Handle v-prefix in auto-tag version computation (#179)
- Allow path-filtered CI workflows to be absent in auto-tag (#180)
- Fetch tags in auto-tag checkout and improve diagnostics (#181)
- Explicitly fetch tags in auto-tag workflow (#182)
- Unset --no-tags config before fetching tags in auto-tag workflow (#183)
- Use explicit tag refspec to fetch tags in auto-tag workflow (#184)
- Add diagnostics for tag fetch failure in auto-tag workflow (#185)
- Diagnose tag visibility with ls-remote and token variants (#186)
- Upload empty SARIF stub when c-cpp analysis is skipped on PRs (#188)
- Skip forwarding headers on noproxy bypass
- Skip forwarding headers on noproxy bypass
- Set initial_tag in cliff.toml so git-cliff bumps from v1.0.0

### Security
- Fatal exit on crypto/rand failure instead of timestamp fallback
- Default -connect-ports to 443 instead of allowing all ports
- Return 502 instead of raw relay when upstream response is unparseable
- Zero password bytes after Kerberos client initialization
[1.1.1]: https://github.com/andrewesweet/spnego-proxy/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/andrewesweet/spnego-proxy/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/andrewesweet/spnego-proxy/releases/tag/v1.0.0

