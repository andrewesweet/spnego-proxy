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
clang-format --dry-run --Werror gss_darwin.c gss_darwin.h

# Fix formatting automatically
clang-format -i gss_darwin.c gss_darwin.h
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
    gss_darwin.c -- -DGSS_USE_APPLE_FRAMEWORK -framework GSS
```

**cppcheck:**

```bash
cppcheck \
    --enable=all \
    --error-exitcode=1 \
    --suppress=missingIncludeSystem \
    --suppress=unusedFunction \
    gss_darwin.c
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
| GSS-API integration tests | go test (INTEGRATION=1) | macOS arm64 only |
