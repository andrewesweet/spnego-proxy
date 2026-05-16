# Extract `internal/proxy` Package — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the proxy logic and its fuzz/unit tests out of `package main` into an importable `internal/proxy` package, with zero observable behaviour change, so ClusterFuzzLite can compile the fuzz targets.

**Architecture:** `package main` keeps only `main.go`, `version.go`, `cli.go` (entrypoint, ldflags version vars, flag parsing). Everything else moves to `internal/proxy` as `package proxy`. Tests move with the code as in-package (`package proxy`) tests, so unexported access is preserved and almost nothing needs exporting. The few identifiers `main` calls across the new boundary are capitalised with `gofmt -r` (AST-safe).

**Tech Stack:** Go 1.25, `git mv`, `gofmt -r`, `go build`, `go test`, `golangci-lint`.

**Spec:** `docs/superpowers/specs/2026-05-16-extract-internal-proxy-package-design.md`

**Refactor discipline:** This is behaviour-preserving. The regression oracle is the **pre-existing test suite staying green** and a **diff that contains no logic hunks** (only file moves, `package` clause changes, identifier capitalisation). All commits use `refactor:` → no version bump.

---

## File Structure

- Root `package main` (stays): `main.go`, `version.go`, `cli.go`, plus the test files that test only `version.go`/`cli.go` symbols (determined in Task 3).
- `internal/proxy/` `package proxy` (new): the 15 logic files + 4 auth files + `gss_darwin.{c,h}` + all test/fuzz files that reference moved symbols + `testdata/fuzz/`.
- Docs touched: `CONTRIBUTING.md` § Fuzzing, `CLAUDE.md` § Fuzzing (path-only edits).

---

## Task 1: Baseline & golden capture

**Files:** none (creates throwaway baseline artifacts under `/tmp`).

- [ ] **Step 1: Confirm branch**

Run: `git -C /home/andre/code/github.com/andrewesweet/spnego-proxy branch --show-current`
Expected: `refactor/extract-internal-proxy`

- [ ] **Step 2: Baseline build + full test suite is green BEFORE any change**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test -count=1 ./... 2>&1 | tee /tmp/baseline-test.log | tail -5
```
Expected: build succeeds; final line `ok  github.com/andrewesweet/spnego-proxy ...` (all tests pass). If anything fails here, STOP — the tree is not clean; do not refactor on a red baseline.

- [ ] **Step 3: Capture CLI golden output (behaviour contract)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
CGO_ENABLED=0 go build -o /tmp/spnego-baseline .
/tmp/spnego-baseline -version > /tmp/golden-version.txt 2>&1; echo "version-exit=$?" >> /tmp/golden-version.txt
/tmp/spnego-baseline -help > /tmp/golden-help.txt 2>&1; echo "help-exit=$?" >> /tmp/golden-help.txt
/tmp/spnego-baseline -nonsuch-flag > /tmp/golden-badflag.txt 2>&1; echo "badflag-exit=$?" >> /tmp/golden-badflag.txt
cat /tmp/golden-version.txt /tmp/golden-help.txt /tmp/golden-badflag.txt
```
Expected: version string printed (`version-exit=0`), usage text (`help-exit=0`), usage+error (`badflag-exit=2`). These three files are the behaviour contract checked in Task 8.

- [ ] **Step 4: No commit** (baseline only).

---

## Task 2: Build the authoritative rename & file-placement manifest

Agent summaries disagreed on a few identifier names (e.g. whether the NO_PROXY matcher type is exported). Ground-truth everything here before moving anything.

**Files:** Create `/tmp/manifest.md` (scratch, not committed).

- [ ] **Step 1: List the production files to move (certain set)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
ls config.go circuit_breaker.go dial.go connect.go direct.go forward.go \
   headers.go noproxy.go response.go errors.go errors_proxy.go server.go \
   auth_gokrb5.go auth_gss_darwin.go auth_notdarwin.go auth_nocgo_darwin.go \
   gss_darwin.c gss_darwin.h
```
Expected: all 18 listed, no "No such file". (15 logic .go + ... adjust if a filename differs — record the actual set in `/tmp/manifest.md` under "MOVE-PROD".)

- [ ] **Step 2: Identify which symbols `main.go` + `cli.go` reference that live in moved files** (these need capitalising)

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
grep -oE '\b(serve|generateViaPseudonym|splitCSV|parseAllowList|resolveNoProxy|newNativeTokenProvider|logLevel|buildTLSConfig|NoProxyMatcher|NewNoProxyMatcher|ProxyConfig|ForwardingConfig|UpstreamTLSConfig|TokenProvider)\b' main.go cli.go version.go | sort -u
echo "--- declarations of the lowercase ones ---"
grep -nE '^(func |type |var |const )(serve|generateViaPseudonym|splitCSV|parseAllowList|resolveNoProxy|newNativeTokenProvider|logLevel)\b|func \([a-zA-Z ]*\) buildTLSConfig' *.go
```
Expected: a list of identifiers. Record in `/tmp/manifest.md` under "RENAME" a table: `old -> New` for every **lowercase** identifier that `main.go`/`cli.go` use but whose declaration is in a MOVE-PROD file. Canonical mapping (confirm each against grep; drop any that are already exported or not actually cross-boundary):

| old | New |
|---|---|
| `serve` | `Serve` |
| `generateViaPseudonym` | `GenerateViaPseudonym` |
| `splitCSV` | `SplitCSV` |
| `parseAllowList` | `ParseAllowList` |
| `resolveNoProxy` | `ResolveNoProxy` |
| `newNativeTokenProvider` | `NewNativeTokenProvider` |
| `logLevel` | `LogLevel` |
| `buildTLSConfig` | `BuildTLSConfig` |

If `grep` shows the NO_PROXY matcher **type** is lowercase (e.g. `noProxyMatcher`) add `noProxyMatcher -> NoProxyMatcher`. If `cli.go`'s `buildProvider` calls a lowercase gokrb5/circuit-breaker constructor that lives in a moved file, add those too (e.g. `newGokrb5TokenProvider -> NewGokrb5TokenProvider`, `newCircuitBreaker… -> NewCircuitBreaker…`). The rule: **any lowercase identifier declared in a MOVE-PROD file and referenced from `main.go`/`cli.go` goes in the RENAME table.**

- [ ] **Step 3: Classify every `*_test.go` by the package it must join**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
for f in *_test.go; do
  echo "=== $f ==="
  grep -oE '\b(versionString|version|commit|parseFlags|cliConfig|buildProvider|normalizeSPN)\b' "$f" | sort -u | tr '\n' ' '
  echo
done
```
Expected: per-file symbol hits. Decision rule recorded in `/tmp/manifest.md` under "TEST-PLACEMENT":
- A test file that references **only** root-staying symbols (`versionString`, `version`, `commit`, `parseFlags`, `cliConfig`, `buildProvider`, `normalizeSPN`) and **no** moved symbol → **STAYS** `package main` (e.g. expect `version_test.go`; possibly `spn_test.go` if `normalizeSPN` is in `cli.go`).
- Every other test file → **MOVES** to `internal/proxy`, `package proxy`.
- A test file that references **both** a root-staying symbol AND moved symbols → flag as "SPLIT" in the manifest and handle in Task 5 Step 4 (rare; likely only `main_test.go` if it tests both `parseFlags` and `serve`). Verify with:
  `grep -nE '\b(parseFlags|cliConfig|buildProvider)\b' main_test.go`

- [ ] **Step 4: No commit** (manifest is scratch).

---

## Task 3: Create package, move production files

**Files:** Create `internal/proxy/`; `git mv` the MOVE-PROD set.

- [ ] **Step 1: Move production files (use the MOVE-PROD list from Task 2)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
mkdir -p internal/proxy
git mv config.go circuit_breaker.go dial.go connect.go direct.go forward.go \
       headers.go noproxy.go response.go errors.go errors_proxy.go server.go \
       auth_gokrb5.go auth_gss_darwin.go auth_notdarwin.go auth_nocgo_darwin.go \
       gss_darwin.c gss_darwin.h internal/proxy/
git status --porcelain | grep '^R' | wc -l
```
Expected: rename count equals the MOVE-PROD file count. (Adjust the file list to the exact MOVE-PROD set recorded in Task 2 Step 1 if any filename differed.)

- [ ] **Step 2: Rewrite `package main` → `package proxy` on moved files only**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy/internal/proxy
for f in *.go; do sed -i '1,5{s/^package main$/package proxy/}' "$f"; done
grep -L '^package proxy' *.go || echo "all moved .go files are package proxy"
```
Expected: `all moved .go files are package proxy`. (The C files `gss_darwin.{c,h}` have no Go package clause — leave them; their `//go:build darwin` header comment is unchanged.)

- [ ] **Step 3: Build is expected to FAIL now (main still references moved symbols)**

Run: `cd /home/andre/code/github.com/andrewesweet/spnego-proxy && CGO_ENABLED=0 go build ./... 2>&1 | head -5`
Expected: FAIL — `main.go`/`cli.go` undefined symbols. This is intentional mid-refactor; fixed by Tasks 4–6.

- [ ] **Step 4: Commit the move (compiles-broken WIP is acceptable mid-refactor on a feature branch)**

```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
git add -A
git commit -m "refactor: move proxy logic files into internal/proxy

Pure git mv + package clause change (main -> proxy). Tree does not
build until main is rewired (next tasks). No logic changes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Move and repackage test files

**Files:** `git mv` every MOVES test file (from Task 2 Step 3) into `internal/proxy/`; keep STAYS files in root.

- [ ] **Step 1: Move the MOVES test files**

Using the TEST-PLACEMENT list from Task 2 Step 3, move every test file classified MOVES. Example (replace the list with the manifest's MOVES set):
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
git mv allowlist_test.go auth_gokrb5_test.go auth_gss_darwin_test.go \
       circuit_breaker_test.go config_fuzz_test.go connect_test.go \
       direct_fuzz_test.go ephemeral_kdc_darwin_test.go errors_test.go \
       forwarding_fidelity_test.go forwarding_headers_test.go \
       framing_conformance_test.go gokrb5_integration_test.go harness_test.go \
       hop_by_hop_test.go integration_gss_darwin_test.go main_test.go \
       noproxy_fuzz_test.go noproxy_integration_test.go noproxy_test.go \
       protocol_edge_cases_test.go proxy_status_test.go response_fuzz_test.go \
       upstream_tls_test.go internal/proxy/
```
Keep in root the STAYS files (expected: `version_test.go`, and `spn_test.go` only if Task 2 found `normalizeSPN` in `cli.go`). Do NOT move SPLIT files yet (handled Task 5 Step 4).

- [ ] **Step 2: Repackage moved test files to `package proxy`**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy/internal/proxy
for f in *_test.go; do sed -i '1,5{s/^package main$/package proxy/}' "$f"; done
grep -L '^package proxy' *_test.go || echo "all moved tests are package proxy"
```
Expected: `all moved tests are package proxy`.

- [ ] **Step 3: Commit**

```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
git add -A
git commit -m "refactor: move proxy tests into internal/proxy as in-package tests

git mv + package clause change. In-package (package proxy) tests keep
unexported access; no test logic changed.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Capitalise the cross-boundary identifiers (gofmt -r)

**Files:** all `.go` in repo (AST-safe rewrite); `main.go`, `cli.go` references updated.

- [ ] **Step 1: Apply each RENAME row with `gofmt -r` repo-wide**

For every `old -> New` row in the Task 2 RENAME manifest, run (substitute names):
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
for rule in \
  'serve -> Serve' \
  'generateViaPseudonym -> GenerateViaPseudonym' \
  'splitCSV -> SplitCSV' \
  'parseAllowList -> ParseAllowList' \
  'resolveNoProxy -> ResolveNoProxy' \
  'newNativeTokenProvider -> NewNativeTokenProvider' \
  'logLevel -> LogLevel' \
  'buildTLSConfig -> BuildTLSConfig' ; do
  gofmt -r "$rule" -w .
done
# Add any extra rows the manifest required (matcher type / provider ctors), same form.
```
Expected: no output (success). `gofmt -r` rewrites the identifier across every file including call sites in `main.go`/`cli.go`.

- [ ] **Step 2: Sanity-check the renames are total (no lowercase survivors at definitions)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
grep -rnE '\bfunc serve\(|\bfunc generateViaPseudonym\(|\bfunc splitCSV\(|\bfunc parseAllowList\(|\bfunc resolveNoProxy\(|\bfunc newNativeTokenProvider\(|\bvar logLevel\b' --include='*.go' . || echo "no old declarations remain"
```
Expected: `no old declarations remain`.

- [ ] **Step 3: Verify no accidental collisions**

Run: `cd /home/andre/code/github.com/andrewesweet/spnego-proxy && gofmt -l . ` (lists malformed files — expect empty) and visually scan `git diff -G'(?i)serve' --stat` for unrelated files. Expected: only intended files changed; `gofmt -l` prints nothing.

- [ ] **Step 4: Handle any SPLIT test file from Task 2**

If a test file was flagged SPLIT (tests both `parseFlags`/`cliConfig` AND moved symbols): separate it. Keep the parse/CLI test functions in a root `package main` file (e.g. leave `main_test.go` in root containing only the `parseFlags`-related tests), and move the moved-symbol test functions into a new `internal/proxy/<name>_test.go` (`package proxy`). Move whole test functions verbatim — do not edit their bodies. If no SPLIT file was flagged, skip this step.

- [ ] **Step 5: No commit yet** (Task 6 finishes the compile; commit together there).

---

## Task 6: Rewire `main.go` / `cli.go` to import `internal/proxy`

**Files:** Modify `main.go`, `cli.go`. `version.go` unchanged.

- [ ] **Step 1: Add the import and qualify cross-package references**

In `main.go` and `cli.go`, add to the import block:
```go
"github.com/andrewesweet/spnego-proxy/internal/proxy"
```
Then qualify every now-external identifier with the `proxy.` selector. After Task 5 the names are capitalised, so the edits are: `Serve(...)` → `proxy.Serve(...)`, `GenerateViaPseudonym()` → `proxy.GenerateViaPseudonym()`, `SplitCSV(...)` → `proxy.SplitCSV(...)`, `ParseAllowList(...)` → `proxy.ParseAllowList(...)`, `ResolveNoProxy(...)` → `proxy.ResolveNoProxy(...)`, `NewNoProxyMatcher(...)` → `proxy.NewNoProxyMatcher(...)`, `*NoProxyMatcher` → `*proxy.NoProxyMatcher`, `ProxyConfig{` → `proxy.Config{` (note: the type was renamed to `Config` per spec — if the manifest kept it `ProxyConfig`, use `proxy.ProxyConfig`), `ForwardingConfig{` → `proxy.ForwardingConfig{`, `UpstreamTLSConfig{` → `proxy.UpstreamTLSConfig{`, `.BuildTLSConfig()` stays a method call on the now-`proxy.UpstreamTLSConfig` value (no selector change), `LogLevel` → `proxy.LogLevel`, `TokenProvider` → `proxy.TokenProvider`, `NewNativeTokenProvider(...)` → `proxy.NewNativeTokenProvider(...)`, gokrb5/circuit-breaker constructors → `proxy.<Name>(...)`.

The compiler drives this: iterate Step 2 ↔ Step 1 until it builds.

- [ ] **Step 2: Build**

Run: `cd /home/andre/code/github.com/andrewesweet/spnego-proxy && CGO_ENABLED=0 go build ./... 2>&1 | head -20`
Expected: eventually succeeds (no output). Each error names an unqualified identifier — prefix it with `proxy.` and rebuild. Do NOT change any logic; only add `proxy.` selectors and the import.

- [ ] **Step 3: `go vet` + module tidy check**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
CGO_ENABLED=0 go vet ./... && cp go.mod /tmp/gomod.before && go mod tidy && diff /tmp/gomod.before go.mod && echo "go.mod unchanged"
```
Expected: vet clean; `go.mod unchanged` (no new dependency — invariant from CLAUDE.md § Fuzzing).

- [ ] **Step 4: Commit**

```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
git add -A
git commit -m "refactor: rewire main to import internal/proxy

Capitalise the cross-boundary identifiers (gofmt -r) and qualify them
with the proxy. selector. Behaviour unchanged; tree builds again.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Move fuzz corpus

**Files:** `git mv testdata/fuzz` → `internal/proxy/testdata/fuzz`.

- [ ] **Step 1: Move testdata**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
git mv testdata internal/proxy/testdata
find internal/proxy/testdata -type f
```
Expected: lists `internal/proxy/testdata/fuzz/FuzzNoProxyMatch/4e3d56e8f8cb2156` (and any other corpus files).

- [ ] **Step 2: Confirm the committed reproducer still replays (in its new package location)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
CGO_ENABLED=0 go test -count=1 -run '^FuzzNoProxyMatch$' ./internal/proxy/ 2>&1 | tail -3
```
Expected: PASS (Go finds `internal/proxy/testdata/fuzz/FuzzNoProxyMatch/` relative to the package).

- [ ] **Step 3: Commit**

```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
git add -A
git commit -m "refactor: move fuzz corpus under internal/proxy/testdata

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Full verification gate (regression oracle)

**Files:** none (verification only).

- [ ] **Step 1: Build both build tags**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
CGO_ENABLED=0 go build ./... && echo "linux/nocgo build OK"
CGO_ENABLED=1 go vet ./internal/proxy/ 2>&1 | tail -2 || true   # darwin cgo path: vet only (full build needs macOS)
```
Expected: `linux/nocgo build OK`. (The darwin GSS cgo build is exercised by macOS CI; locally only the non-cgo path is provable.)

- [ ] **Step 2: Full test suite green (must match the Task 1 baseline)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
CGO_ENABLED=0 go test -count=1 ./... 2>&1 | tee /tmp/after-test.log | tail -5
```
Expected: all packages `ok`. Compare pass set against `/tmp/baseline-test.log` — the same tests run, now under `github.com/andrewesweet/spnego-proxy` (main) and `.../internal/proxy`. No test removed, none newly failing.

- [ ] **Step 3: Linter**

Run: `cd /home/andre/code/github.com/andrewesweet/spnego-proxy && golangci-lint run 2>&1 | tail -5`
Expected: no findings (clean exit). If `golangci-lint` absent locally, note it; CI enforces it.

- [ ] **Step 4: CLI behaviour contract unchanged (golden diff)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
CGO_ENABLED=0 go build -o /tmp/spnego-after .
/tmp/spnego-after -version > /tmp/after-version.txt 2>&1; echo "version-exit=$?" >> /tmp/after-version.txt
/tmp/spnego-after -help > /tmp/after-help.txt 2>&1; echo "help-exit=$?" >> /tmp/after-help.txt
/tmp/spnego-after -nonsuch-flag > /tmp/after-badflag.txt 2>&1; echo "badflag-exit=$?" >> /tmp/after-badflag.txt
diff /tmp/golden-version.txt /tmp/after-version.txt && \
diff /tmp/golden-help.txt /tmp/after-help.txt && \
diff /tmp/golden-badflag.txt /tmp/after-badflag.txt && echo "CLI CONTRACT UNCHANGED"
```
Expected: `CLI CONTRACT UNCHANGED` (zero diff, identical exit codes). Any diff is a behaviour regression — STOP and fix before continuing.

- [ ] **Step 5: No-logic-hunk review**

Run: `cd /home/andre/code/github.com/andrewesweet/spnego-proxy && git diff master --stat | tail -3 && git diff master -- internal/proxy/ | grep -E '^[+-]' | grep -vE '^[+-]{3} |^[+-]package |^[+-]$' | grep -viE 'serve|generateViaPseudonym|splitCSV|parseAllowList|resolveNoProxy|newNativeTokenProvider|logLevel|buildTLSConfig|proxy\.' | head -30`
Expected: the second command prints **nothing** — the only content changes are `package` clauses and the capitalised identifiers. If it prints real logic lines, a logic edit slipped in during the mechanical rename — revert that hunk.

- [ ] **Step 6: No commit** (gate only).

---

## Task 9: Fix documentation paths forced by the move

**Files:** Modify `CONTRIBUTING.md` (§ Fuzzing), `CLAUDE.md` (§ Fuzzing).

- [ ] **Step 1: Update the local fuzz command and corpus path in `CONTRIBUTING.md`**

In `CONTRIBUTING.md` § Fuzzing, change the run-one-target command from operating on `.` to `./internal/proxy`:
- Old: `go test -run '^$' -fuzz '^FuzzNoProxyMatch$' -fuzztime=60s .`
- New: `go test -run '^$' -fuzz '^FuzzNoProxyMatch$' -fuzztime=60s ./internal/proxy`

And change the reproducer-path sentence from `testdata/fuzz/<Target>/` to `internal/proxy/testdata/fuzz/<Target>/`.

- [ ] **Step 2: Update the matching line in `CLAUDE.md`**

In `CLAUDE.md` § Fuzzing, change `committed under testdata/fuzz/<Target>/ and replayed free by go test ./...` to `committed under internal/proxy/testdata/fuzz/<Target>/ and replayed free by go test ./...`.

- [ ] **Step 3: Markdown lint (CI parity)**

Run: `cd /home/andre/code/github.com/andrewesweet/spnego-proxy && npx --yes markdownlint-cli2 "CONTRIBUTING.md" "CLAUDE.md" 2>&1 | tail -3`
Expected: no errors. If `npx` unavailable, note it; CI enforces.

- [ ] **Step 4: Commit**

```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
git add CONTRIBUTING.md CLAUDE.md
git commit -m "docs: fix fuzz paths after internal/proxy extraction

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Push and open PR

**Files:** none.

- [ ] **Step 1: Push**

Run: `cd /home/andre/code/github.com/andrewesweet/spnego-proxy && git push -u origin refactor/extract-internal-proxy 2>&1 | tail -2`
Expected: branch published.

- [ ] **Step 2: Open PR (not draft — this is mergeable on its own)**

Run:
```bash
cd /home/andre/code/github.com/andrewesweet/spnego-proxy
gh pr create --base master --title "refactor: extract proxy logic into internal/proxy package" --body "$(cat <<'BODY'
Behaviour-preserving extraction of the proxy logic + fuzz/unit tests into an importable internal/proxy package. Prerequisite for the ClusterFuzzLite migration (PR #224), which cannot fuzz package main.

Spec: docs/superpowers/specs/2026-05-16-extract-internal-proxy-package-design.md
Plan: docs/superpowers/plans/2026-05-16-extract-internal-proxy-package.md

- Pure git mv + package clause change + gofmt -r capitalisation of the few cross-boundary identifiers. No logic hunks (verified).
- All pre-existing tests pass unchanged; CLI -version/-help/bad-flag output and exit codes byte-identical to master.
- go.mod unchanged (no new dependency). refactor: -> no version bump.
- Follow-on: PR #224 rebases and flips .clusterfuzzlite/build.sh module path to .../internal/proxy.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
BODY
)" 2>&1 | tail -1
```
Expected: PR URL printed.

- [ ] **Step 3: Confirm CI is green on the PR**

Run: `gh pr checks --repo andrewesweet/spnego-proxy --watch 2>&1 | tail -15` (Build and Test, golangci-lint, govulncheck, CodeQL, lint-markdown).
Expected: all required checks pass. Investigate any failure before requesting review.

---

## Out of scope (do NOT do here)

- Editing the ClusterFuzzLite workflows / `.clusterfuzzlite/` — that is PR #224's rebase, a separate follow-on.
- Any logic change, new test, dependency change, entrypoint redesign, or unrelated cleanup.

## Self-review (completed by plan author)

- **Spec coverage:** layout (T3/T4/T7), exported surface incl. `LogLevel`/`BuildTLSConfig` (T2/T5), `version.go` & ldflags untouched (T6 keeps `version.go`; no ldflags task — correct), invariants (T8 golden + no-logic-hunk), doc path fixes (T9), CFL rebase noted as out-of-scope follow-on. Covered.
- **Placeholders:** none — identifier set is ground-truthed in T2 with exact grep, not assumed; the canonical RENAME table is given with a precise inclusion rule.
- **Type consistency:** `Config` vs `ProxyConfig` flagged explicitly in T6 Step 1 (use whatever T2 confirms); `LogLevel`, `BuildTLSConfig`, `Serve`, `GenerateViaPseudonym`, `SplitCSV`, `ParseAllowList`, `ResolveNoProxy`, `NewNativeTokenProvider` used consistently across T5/T6/T8.
