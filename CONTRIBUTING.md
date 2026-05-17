# Contributing

## Prerequisites

- [Go 1.25+](https://go.dev/dl/)
- [clang-format](https://clang.llvm.org/docs/ClangFormat.html) (for C code
  formatting)

Optional (for running macOS GSS-API integration tests):

- [MIT Kerberos](https://web.mit.edu/kerberos/) via Homebrew: `brew install krb5`
  (macOS only)

Optional (for running the full lint suite locally):

- [golangci-lint v2](https://golangci-lint.run/welcome/install/)
- [markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2)
- [actionlint](https://github.com/rhysd/actionlint)
- [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) (macOS only)
- [cppcheck](http://cppcheck.net/) (macOS only)
- [git-cliff](https://git-cliff.org/) (for changelog generation and version
  bumping)

## Building

### macOS (with CGO for GSS-API support)

```bash
CGO_ENABLED=1 go build -o spnego-proxy .
```

### Linux (pure Go, gokrb5 fallback)

```bash
CGO_ENABLED=0 go build -o spnego-proxy .
```

## Testing

### Unit tests

```bash
go test -v -count=1 ./...
```

On macOS with CGO enabled, this includes the GSS-API unit tests. On Linux
(`CGO_ENABLED=0`), only the gokrb5 path is tested.

### macOS GSS-API integration tests

The integration tests exercise the real Apple Heimdal GSS-API code path against
an ephemeral MIT Kerberos KDC. They require macOS and MIT krb5 from Homebrew.

#### Install MIT Kerberos

```bash
brew install krb5
```

This installs MIT Kerberos utilities alongside (not replacing) the built-in
macOS Heimdal. The system GSS framework is unaffected.

#### Run integration tests

```bash
export PATH="$(brew --prefix krb5)/bin:$(brew --prefix krb5)/sbin:$PATH"
INTEGRATION=1 go test -v -count=1 ./...
```

To run only the GSS-API integration tests:

```bash
export PATH="$(brew --prefix krb5)/bin:$(brew --prefix krb5)/sbin:$PATH"
INTEGRATION=1 go test -v -count=1 -run 'Test.*KDC\|Test.*GSS.*KDC' ./...
```

The tests are gated by `//go:build darwin` and the `INTEGRATION` environment
variable — they skip automatically on Linux and when `INTEGRATION` is unset.
They also skip if MIT krb5 is not installed.

### Fuzzing

The proxy has native Go fuzz targets (`go test -fuzz`) covering the inputs an
unprivileged client or a malicious origin controls. Seed corpora live in
`f.Add` calls; discovered crash reproducers are committed under
`internal/proxy/testdata/fuzz/<Target>/` and replayed for free by the ordinary
`go test ./...` run (so a fixed bug stays fixed).

The same targets are continuously fuzzed by **ClusterFuzzLite** on GitHub
Actions: code-change fuzzing on every PR (`cflite_pr.yml`, fork-safe, no
storage), corpus seeding on push to `master` (`cflite_cont.yml`), and a nightly
batch → prune → coverage pipeline (`cflite_batch.yml`). Corpus, crashes, and
the coverage report live in a **separate storage repo**
(`andrewesweet/spnego-proxy-fuzz-corpus`). ClusterFuzzLite clones the storage
repo *inside* the OSS-Fuzz build container, where there is no `ssh` binary and
the runner's `~/.ssh` is not mounted, so an SSH deploy key cannot be used
here (unlike the Homebrew tap, whose clone is host-side). The workflows
authenticate with a **fine-grained PAT scoped to only the corpus repo**
(Contents: read/write), stored as the `FUZZ_CORPUS_TOKEN` secret; GitHub masks
it in logs and the repo holds non-sensitive corpus/coverage data. Build
integration lives in `.clusterfuzzlite/` (`project.yaml`, `Dockerfile`,
`build.sh`).

Run one target locally:

```bash
go test -run '^$' -fuzz '^FuzzNoProxyMatch$' -fuzztime=60s ./internal/proxy
```

Replay only the committed corpus (no discovery), as CI does:

```bash
go test -count=1 ./...
```

#### When to add a target

Add a target when you introduce or change code that parses or makes a
policy/framing decision on attacker-influenced input: request authority,
headers, client address, or an upstream response. Do **not** fuzz the standard
library directly (the Go team already does) — fuzz *our* logic, optionally
*through* a stdlib parser used as part of the chain.

#### Rules (these are load-bearing — they were each a trap)

1. **No new dependency.** This is a security-sensitive proxy with a deliberately
   small dependency set. A differential oracle must use only the standard
   library or a package already in `go.mod`. In particular
   `golang.org/x/net/http/httpproxy` and `golang.org/x/net/http/httpguts`
   transitively pull `golang.org/x/text` — do **not** import them. Write a
   clean-room reference instead. Verify with `go mod tidy` producing no diff.
2. **Sound oracle, or crash-only.** A differential assertion must not flag
   intended behaviour. Gate on parseability; assert only the
   security-meaningful direction (e.g. "accepted ⇒ literally permitted", not a
   re-derivation that re-implements the function); never bake the production
   implementation's semantics into the reference. If you cannot construct a
   sound oracle, ship the target as no-panic / invariant-only.
3. **OSS-Fuzz portable.** Entropy only via `[]byte`/`string`/scalars in
   `f.Fuzz`; targets must be hermetic and deterministic (no network, files,
   clock, randomness, global state) and build with `CGO_ENABLED=0`. This is
   what lets ClusterFuzzLite compile the native targets unchanged via
   `compile_native_go_fuzzer`.
4. **Reproducer hygiene.** If a target fails: a *real* bug → fix the production
   code and commit the reproducer (it becomes a regression seed) with a `fix:`
   commit; an *unsound oracle* → tighten the predicate and **delete** the noise
   reproducer (do not commit it).
5. **Register the target.** Add a `compile_native_go_fuzzer` line for every new
   `Fuzz*` function in `.clusterfuzzlite/build.sh` so ClusterFuzzLite builds it.
   The legacy nightly `Fuzz` workflow (`.github/workflows/fuzz.yml`) is retained
   until the ClusterFuzzLite batch is validated against the storage repo, then
   removed; while it exists, also add the name to its matrix.

## Formatting

All code must be formatted before committing. CI will reject unformatted code.

### Go formatting

Go code is formatted with [gofmt](https://pkg.go.dev/cmd/gofmt) (checked via
[golangci-lint](https://golangci-lint.run/)).

```bash
# Check for formatting issues
gofmt -d .

# Fix formatting automatically
gofmt -w .
```

### C formatting

C code follows the
[Google C++ style](https://google.github.io/styleguide/cppguide.html), enforced
by [clang-format](https://clang.llvm.org/docs/ClangFormat.html). The
`.clang-format` file in the repository root configures the style.

```bash
# Check for formatting issues
clang-format --dry-run --Werror internal/proxy/gss_darwin.c internal/proxy/gss_darwin.h

# Fix formatting automatically
clang-format -i internal/proxy/gss_darwin.c internal/proxy/gss_darwin.h
```

### Markdown formatting

Markdown is checked by
[markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2). The
`.markdownlint-cli2.yaml` file in the repository root configures the rules.

```bash
# Check for lint issues
npx markdownlint-cli2 "**/*.md"

# Fix issues automatically (where possible)
npx markdownlint-cli2 --fix "**/*.md"
```

## Linting

### Go linting

```bash
golangci-lint run
```

This runs the linters configured in `.golangci.yml`, including `gosec`,
`revive`, `errorlint`, and others.

### C static analysis (macOS only)

The C static analysis tools require the macOS GSS framework headers and must be
run on macOS.

**clang-tidy:**

```bash
SDK_PATH=$(xcrun --show-sdk-path)
clang-tidy \
    -checks='-*,clang-analyzer-*,bugprone-*,-bugprone-easily-swappable-parameters,performance-*,portability-*' \
    -isystem "$SDK_PATH/usr/include" \
    internal/proxy/gss_darwin.c -- -DGSS_USE_APPLE_FRAMEWORK -framework GSS
```

**cppcheck:**

```bash
cppcheck \
    --enable=all \
    --error-exitcode=1 \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    internal/proxy/gss_darwin.c
```

### Workflow linting

```bash
actionlint
```

## CI checks

Pull requests run the following checks automatically:

| Check | Tool | Scope |
| --- | --- | --- |
| Go formatting | gofmt (via golangci-lint) | `*.go` |
| Go linting | golangci-lint v2 | `*.go` |
| Go vulnerability scan | govulncheck | Go dependencies |
| C formatting | clang-format (Google style) | `*.c`, `*.h` |
| C static analysis | clang-tidy, cppcheck | `*.c` (macOS) |
| Markdown linting | markdownlint-cli2 | `*.md` |
| Workflow linting | actionlint | `.github/workflows/` |
| Security analysis | CodeQL | Go, C, Actions |
| Build + unit tests | go build, go test | macOS (CGO) + Linux |
| PR title format | action-semantic-pull-request | PR titles |
| GSS-API integration tests | go test (INTEGRATION=1) | macOS arm64 only |

## Versioning

This project follows
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). The public
API for SemVer purposes is the CLI contract surface: command-line flags (names,
types, and defaults), exit codes, stdout/stderr behavior, HTTP response headers
and error format, and CONNECT tunneling behavior.

| Change | Version bump |
| --- | --- |
| New flag with backward-compatible default | Minor |
| Bug fix or security fix | Patch |
| Performance improvement | Patch |
| Remove or rename a flag | **Major** |
| Change a flag's default value | **Major** |
| Change exit code semantics | **Major** |
| Change log output or error response format | **Major** |

To preview the next version based on unreleased commits:

```bash
git cliff --bumped-version
```

## Commit messages

This project follows
[Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Commit types drive both the changelog and the SemVer version bump.

### Format

```text
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

### Allowed types

| Type | When to use | SemVer effect |
| --- | --- | --- |
| feat | New feature or capability | Minor |
| fix | Bug fix | Patch |
| docs | Documentation only | None |
| refactor | Code restructuring without behavior change | None |
| test | Adding or modifying tests | None |
| perf | Performance improvement | Patch |
| ci | CI/CD configuration | None |
| build | Build system or dependency changes | None |
| chore | Maintenance tasks | None |

### Scopes

Optional scopes: `security`, `deps`

### Breaking changes

Append `!` after the type/scope to signal a major version bump:

```text
feat!: rename -addr flag to -listen

BREAKING CHANGE: Users must update scripts to use -listen instead of -addr.
```

## Changelog

This project maintains a [CHANGELOG.md](CHANGELOG.md) following
[Keep a Changelog v1.1.0](https://keepachangelog.com/en/1.1.0/).

The changelog is generated from conventional commit messages using
[git-cliff](https://git-cliff.org/). To preview unreleased changes:

```bash
git cliff --unreleased
```

To prepare a release changelog:

```bash
git cliff --tag vX.Y.Z -o CHANGELOG.md
```

## Releasing

Releases are cut from `master` using semantic version tags. The two-stage CI
pipeline (`build-release.yml` → `release.yml`) handles building, packaging, and
publishing automatically.

### Automatic releases

The **Auto Tag** workflow (`auto-tag.yml`) automates the tag-and-release cycle.
When a pull request is merged to `master`:

1. The "Build and Test" workflow runs.
2. On success, Auto Tag verifies all required CI checks passed for the commit.
3. It runs `git cliff --bumped-version` to compute the next SemVer version.
4. If a version bump is needed, it generates the changelog, commits it, creates
   the tag, and pushes — triggering the release pipeline.

**Commit types that trigger a release:**

- `feat` → minor bump
- `fix`, `fix(security)`, `perf` → patch bump
- Breaking changes (`!` suffix or `BREAKING CHANGE` footer) → major bump

**Commit types that do NOT trigger a release:**

- `docs`, `refactor`, `test`, `ci`, `build`, `chore`

This means documentation-only or refactoring PRs merge cleanly without producing
an unwanted release.

### Manual releases (fallback)

For controlled release timing or when the auto-tag workflow is not available, you
can tag manually.

### Release prerequisites

- Push access to the repository (for tagging)
- [git-cliff](https://git-cliff.org/) (for changelog preview)

### Steps

1. Ensure all changes are merged to `master`.
2. Preview the next version and unreleased changelog:

   ```bash
   git cliff --bumped-version
   git cliff --unreleased
   ```

3. Generate the changelog and commit:

   ```bash
   git cliff --tag vX.Y.Z -o CHANGELOG.md
   git add CHANGELOG.md
   git commit -m "docs: update changelog for vX.Y.Z"
   ```

4. Tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin master --tags
   ```

5. The release workflow automatically:
   - Builds binaries for darwin/amd64, darwin/arm64, and linux/amd64
   - Embeds version and commit hash via ldflags (`-version` flag)
   - Packages each as `spnego-proxy_vX.Y.Z_<os>_<arch>.tar.gz` (binary +
     LICENSE + README)
   - Generates SBOM (SPDX JSON) per binary
   - Creates build provenance and SBOM attestations
   - Generates SHA-256 checksums
   - Creates a draft GitHub release, then publishes it

6. Review the published release on GitHub.

### Release artifacts

Each release includes:

| Artifact | Description |
| --- | --- |
| `spnego-proxy_vX.Y.Z_<os>_<arch>.tar.gz` | Binary archive with LICENSE and README |
| `spnego-proxy-<os>-<arch>.sbom.spdx.json` | Software Bill of Materials |
| `checksums-sha256.txt` | SHA-256 checksums for all artifacts |

### Verifying a release

```bash
# Verify build provenance attestation
gh attestation verify spnego-proxy_vX.Y.Z_linux_amd64.tar.gz \
  -R andrewesweet/spnego-proxy

# Check embedded version
tar xzf spnego-proxy_vX.Y.Z_linux_amd64.tar.gz
./spnego-proxy -version
```

### Pre-release tags

Tags with a pre-release suffix (e.g., `v1.0.0-rc.1`) are automatically marked
as pre-releases on GitHub. Use these for validation before cutting a stable
release.

### Immutable releases

Once a release is published, assets and tags should not be modified or deleted.
Enable GitHub's "Release immutability" setting under Settings → Releases for
enforcement.

## Security

A STRIDE threat model of the codebase is maintained in
[docs/threat-model/](docs/threat-model/README.md). Security-related issues are
tracked with the
[`threat-model`](https://github.com/andrewesweet/spnego-proxy/labels/threat-model)
label.
