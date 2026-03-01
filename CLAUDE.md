# CLAUDE.md

## Project

spnego-proxy is a Go 1.25 SPNEGO/Kerberos HTTP proxy.

## Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

The public API for SemVer purposes is the **CLI contract surface**: command-line
flags (names, types, and defaults), exit codes, stdout/stderr behavior, HTTP
response headers and error format, and CONNECT tunneling behavior.

### What constitutes a breaking change

Any of the following require a **major** version bump:

- Removing or renaming a CLI flag
- Changing a flag's default value
- Changing exit code semantics
- Changing the log output format (JSON → text, stderr → stdout)
- Changing the HTTP error response body format
- Changing default HTTP header behavior (e.g., stopping Via header emission)

### Non-breaking changes

- New flag with a backward-compatible default → **minor**
- Bug fix or security fix → **patch**
- Performance improvement → **patch**

### Conventional Commits → SemVer

- `feat:` → minor bump
- `fix:` / `fix(security):` → patch bump
- Any type with `!` (e.g., `feat!:`) or `BREAKING CHANGE` footer → major bump
- `perf:`, `refactor:`, `docs:`, `test:`, `ci:`, `build:`, `chore:` → no bump

To preview the next version: `git cliff --bumped-version`

## Commit Convention

This project uses [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
All commit messages MUST follow this format:

    <type>[optional scope][!]: <description>

    [optional body]

    [optional footer(s)]

### Allowed types

| Type | Purpose |
| --- | --- |
| feat | New feature or capability |
| fix | Bug fix |
| docs | Documentation only |
| refactor | Code restructuring without behavior change |
| test | Adding or modifying tests |
| perf | Performance improvement |
| ci | CI/CD configuration |
| build | Build system or dependency changes |
| chore | Maintenance tasks |

### Scopes

Optional: `security`, `deps`

### Breaking changes

Append `!` after the type/scope and explain in the commit body:

    feat!: rename -addr flag to -listen

    The -addr flag has been renamed to -listen for consistency.

    BREAKING CHANGE: Users must update their scripts to use -listen instead of -addr.

### Examples

- `feat: add SOCKS5 upstream support`
- `fix(security): sanitize proxy headers`
- `feat!: change default connect-ports to allow all`
- `docs: update changelog for v0.2.0`
- `refactor: extract TLS config builder`
- `test: add circuit breaker timeout tests`

## Changelog

This project maintains a CHANGELOG.md following [Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/).

The changelog is generated from conventional commit messages using [git-cliff](https://git-cliff.org/).
Configuration is in `cliff.toml`.

Preview unreleased changes:

    git cliff --unreleased

Preview the next SemVer version (computed from commits since last tag):

    git cliff --bumped-version

Prepare a release changelog:

    git cliff --tag vX.Y.Z -o CHANGELOG.md

## Go Version

Go 1.25. Use modern Go idioms (wg.Go, SplitSeq, t.Context).

## Testing

    go test -v -count=1 ./...

## Linting

    golangci-lint run

## Release Process

### Creating a Release

1. Ensure all changes are merged to `master`
2. Preview: `git cliff --bumped-version` and `git cliff --unreleased`
3. Tag: `git tag vX.Y.Z && git push origin vX.Y.Z`
4. The Release workflow automatically:
   - Builds binaries for darwin/amd64, darwin/arm64, linux/amd64
   - Packages each as `spnego-proxy_vX.Y.Z_<os>_<arch>.tar.gz` with LICENSE and README
   - Generates SBOM (SPDX JSON) for each binary
   - Creates build provenance and SBOM attestations
   - Generates SHA-256 checksums
   - Publishes a GitHub release with all assets

### Verifying a Release

    gh attestation verify spnego-proxy_v0.1.0_linux_amd64.tar.gz -R andrewesweet/spnego-proxy

### GitHub Immutable Releases

Once published, release assets and tags cannot be modified or deleted.

**One-time admin setup:** Settings > Releases > Enable "Release immutability"
