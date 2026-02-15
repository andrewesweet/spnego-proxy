# Build and Release Proposal: SLSA Level 3 with Immutable Releases

## Summary

This proposal introduces a formal build and release mechanism for `spnego-proxy`
using GitHub Actions, targeting **SLSA v1.0 Build Level 3** provenance and
**GitHub Immutable Releases** for supply chain integrity.

## Goals

1. **Multi-platform macOS builds** -- Intel (amd64) and Apple Silicon (arm64)
   with CGO enabled for native GSS-API framework linkage.
2. **Linux amd64 build** -- CGO disabled, using pure-Go gokrb5 fallback.
3. **SLSA v1.0 Build Level 3** -- Using GitHub-native artifact attestations
   (`actions/attest-build-provenance`) inside a reusable workflow to satisfy the
   non-falsifiability requirement.
4. **Immutable releases** -- Leveraging GitHub's immutable release feature (GA
   October 2025) so that published release assets and tags cannot be modified.
5. **Verification** -- End users can verify provenance via `gh attestation
   verify`.

---

## Background: SLSA Levels and GitHub's Attestation Model

### SLSA v1.0 Build Levels

| Level | Requirement | How We Meet It |
|-------|-------------|----------------|
| L1 | Build process exists and produces provenance | GitHub Actions workflow produces signed attestation |
| L2 | Hosted build service; signed, non-falsifiable provenance | `actions/attest-build-provenance` generates Sigstore-signed in-toto attestation |
| L3 | Build definition comes from an external, hardened source | Build logic lives in a **reusable workflow** called from the release workflow, isolating build instructions from the caller |

**Key insight for L3:** Artifact attestations alone provide L2. To reach L3, the
build _must_ occur inside a **reusable workflow** that is defined outside the
calling workflow. This provides isolation -- the caller cannot tamper with the
build instructions. The reusable workflow generates attestations, and the
provenance metadata records which reusable workflow was invoked, allowing
verification with `--signer-workflow`.

### GitHub Immutable Releases (GA October 2025)

When enabled on a repository, any published release becomes immutable:

- Release assets cannot be added, modified, or deleted after publication.
- The associated Git tag cannot be moved or deleted (permanent reservation).
- A **release attestation** is automatically generated (in-toto release
  predicate with `releaseId`, `databaseId`, and `purl`).

**Critical workflow implication:** Releases must be created as **drafts** first,
assets attached to the draft, and then **published**. Any action that creates and
immediately publishes a release will fail when trying to upload assets
afterward.

**Enabling:** Repository Settings > Code security > Supply chain > Immutable
releases (checkbox). Can also be enforced at the organization level.

Sources:
- [GitHub Docs: Artifact Attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [GitHub Docs: SLSA v1 Build Level 3 with Reusable Workflows](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3)
- [GitHub Docs: Immutable Releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
- [GitHub Community Discussion: Immutable Releases Public Preview](https://github.com/orgs/community/discussions/171210)
- [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)

---

## Architecture

The design uses **two workflow files** to achieve SLSA Build Level 3:

```
 Tag push (vX.Y.Z)
       │
       ▼
 ┌─────────────────────────────┐
 │  release.yml (caller)       │  ← Triggered on tag push
 │                             │
 │  1. Calls reusable workflow │
 │  2. Downloads artifacts     │
 │  3. Creates draft release   │
 │  4. Uploads assets to draft │
 │  5. Publishes release       │
 └──────────┬──────────────────┘
            │ workflow_call
            ▼
 ┌─────────────────────────────┐
 │  build-release.yml          │  ← Reusable workflow
 │  (reusable)                 │
 │                             │
 │  Jobs:                      │
 │  ┌───────────────────────┐  │
 │  │ build-macos           │  │  macOS runner, matrix: [amd64, arm64]
 │  │  → go build (CGO=1)   │  │  Builds darwin binaries
 │  │  → attest provenance  │  │  Signs each binary
 │  └───────────────────────┘  │
 │  ┌───────────────────────┐  │
 │  │ build-linux           │  │  Ubuntu runner
 │  │  → go build (CGO=0)   │  │  Builds linux-amd64 binary
 │  │  → attest provenance  │  │  Signs the binary
 │  └───────────────────────┘  │
 └─────────────────────────────┘
```

### Why Two Files?

SLSA v1.0 Build Level 3 requires that the build definition is **external** to
the calling workflow. By placing all build and attestation logic in a reusable
workflow (`build-release.yml`), we ensure:

1. The caller (`release.yml`) cannot modify build instructions at invocation
   time.
2. The attestation provenance records the exact reusable workflow ref that was
   invoked.
3. Verifiers can pin trust to the reusable workflow using `--signer-workflow`.

---

## Proposed Workflow Files

### File 1: `.github/workflows/build-release.yml` (Reusable Workflow)

This is the hardened build workflow that external callers invoke. It performs the
actual compilation and attestation.

```yaml
name: Build Release Binaries

on:
  workflow_call:
    inputs:
      go-version:
        description: 'Go version to use for building'
        required: true
        type: string

permissions: {}  # Minimal permissions at workflow level; set per-job

jobs:
  build-macos:
    runs-on: macos-latest
    permissions:
      contents: read
      id-token: write       # Required for Sigstore OIDC token
      attestations: write   # Required to persist attestations
    strategy:
      matrix:
        arch: ['amd64', 'arm64']
    steps:
      - uses: actions/checkout@v4   # Pin to hash in implementation

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ inputs.go-version }}

      - name: Build (darwin/${{ matrix.arch }})
        env:
          GOARCH: ${{ matrix.arch }}
          GOOS: darwin
          CGO_ENABLED: "1"
          CC: ${{ matrix.arch == 'amd64' && 'clang -arch x86_64' || 'clang -arch arm64' }}
        run: go build -v -trimpath -o spnego-proxy-darwin-${{ matrix.arch }} .

      - name: Verify binary architecture
        run: |
          file spnego-proxy-darwin-${{ matrix.arch }}
          otool -L spnego-proxy-darwin-${{ matrix.arch }}

      - name: Verify GSS framework linkage
        run: otool -L spnego-proxy-darwin-${{ matrix.arch }} | grep -i GSS

      - name: Attest build provenance
        uses: actions/attest-build-provenance@v3
        with:
          subject-path: spnego-proxy-darwin-${{ matrix.arch }}

      - name: Upload binary
        uses: actions/upload-artifact@v4
        with:
          name: spnego-proxy-darwin-${{ matrix.arch }}
          path: spnego-proxy-darwin-${{ matrix.arch }}

  build-linux:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ inputs.go-version }}

      - name: Build (linux/amd64)
        env:
          CGO_ENABLED: "0"
          GOOS: linux
          GOARCH: amd64
        run: go build -v -trimpath -o spnego-proxy-linux-amd64 .

      - name: Verify binary
        run: file spnego-proxy-linux-amd64

      - name: Attest build provenance
        uses: actions/attest-build-provenance@v3
        with:
          subject-path: spnego-proxy-linux-amd64

      - name: Upload binary
        uses: actions/upload-artifact@v4
        with:
          name: spnego-proxy-linux-amd64
          path: spnego-proxy-linux-amd64
```

**Design notes:**
- **`-trimpath`** is added to `go build` to strip local filesystem paths from
  the binary, improving reproducibility and avoiding information leakage.
- Each binary gets its **own attestation**, so consumers can verify individual
  platform artifacts.
- The workflow accepts `go-version` as an input so the caller can pin the exact
  Go version used for a release.
- Action references should be pinned to full commit SHAs in the actual
  implementation (consistent with existing workflows in this repo).

### File 2: `.github/workflows/release.yml` (Caller Workflow)

This workflow triggers on version tag pushes and orchestrates the release
process.

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions: {}  # Minimal at workflow level

jobs:
  build:
    uses: ./.github/workflows/build-release.yml  # Reusable workflow call
    with:
      go-version: '1.23'   # Pin to latest stable for releases
    permissions:
      contents: read
      id-token: write
      attestations: write

  release:
    needs: build
    runs-on: ubuntu-latest
    permissions:
      contents: write   # Required to create releases
    steps:
      - name: Download all artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts/

      - name: Generate checksums
        run: |
          cd artifacts
          find . -type f -name 'spnego-proxy-*' -exec mv {} . \;
          shasum -a 256 spnego-proxy-* > checksums-sha256.txt
          cat checksums-sha256.txt

      - name: Create draft release and upload assets
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TAG: ${{ github.ref_name }}
        run: |
          cd artifacts
          gh release create "$TAG" \
            --repo "$GITHUB_REPOSITORY" \
            --draft \
            --generate-notes \
            spnego-proxy-darwin-amd64 \
            spnego-proxy-darwin-arm64 \
            spnego-proxy-linux-amd64 \
            checksums-sha256.txt

      - name: Publish release (makes it immutable)
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          TAG: ${{ github.ref_name }}
        run: |
          gh release edit "$TAG" \
            --repo "$GITHUB_REPOSITORY" \
            --draft=false
```

**Design notes:**
- The release is created as a **draft** first, with all assets attached in a
  single `gh release create` call, then published separately. This is the
  required pattern for immutable releases -- assets cannot be added after
  publication.
- `--generate-notes` auto-generates release notes from merged PRs and commits.
- A `checksums-sha256.txt` file is included as a release asset for additional
  integrity verification.
- The `gh` CLI is used instead of `softprops/action-gh-release` because the
  latter has [known incompatibilities](https://github.com/softprops/action-gh-release/issues/653)
  with immutable releases as of late 2025.

---

## Repository Configuration

### 1. Enable Immutable Releases

Navigate to: **Repository Settings > Code security > Supply chain > Immutable
releases** and enable the checkbox.

Or via the REST API:

```
PUT /repos/{owner}/{repo}/immutable-releases
```

**Important caveats:**
- Once a tag is associated with an immutable release, it is **permanently
  reserved** -- even after deleting the release and tag.
- Test the workflow with a pre-release tag (e.g., `v0.0.1-rc1`) before the first
  real release.

### 2. Branch Protection / Tag Protection

Consider adding a tag protection rule for `v*` tags to prevent unauthorized tag
creation. This complements immutable releases by controlling _who_ can trigger
the release workflow.

### 3. Dependabot

The existing Dependabot configuration already covers `github-actions` updates,
which will keep the action references current. No changes needed.

---

## Verification

End users can verify the provenance of any released binary:

```bash
# Verify a specific binary against the repository
gh attestation verify spnego-proxy-darwin-arm64 \
  --repo montag451/spnego-proxy

# Verify with a specific signer workflow (stronger guarantee)
gh attestation verify spnego-proxy-darwin-arm64 \
  --repo montag451/spnego-proxy \
  --signer-workflow .github/workflows/build-release.yml

# Verify the release attestation (generated by immutable releases)
gh attestation verify spnego-proxy-darwin-arm64 \
  --repo montag451/spnego-proxy \
  --predicate-type https://in-toto.io/attestation/release/v0.1
```

---

## Migration / Rollout Plan

### Phase 1: Add Workflow Files

1. Create `.github/workflows/build-release.yml` (reusable build workflow).
2. Create `.github/workflows/release.yml` (caller release workflow).
3. Pin all action references to full commit SHAs (matching repo convention).

### Phase 2: Enable Repository Features

1. Enable immutable releases in repository settings.
2. Optionally add tag protection rules for `v*`.

### Phase 3: Test

1. Push a test tag (e.g., `v0.0.1-test.1`) to trigger the full pipeline.
2. Verify the draft-then-publish flow works correctly.
3. Verify attestations are generated and verifiable.
4. Delete the test release (immutable releases can still be deleted by owners).

### Phase 4: First Real Release

1. Tag the desired commit with the release version (e.g., `v1.0.0`).
2. The workflow triggers automatically, builds all platform binaries, attests
   them, and publishes an immutable release.

---

## Relationship to Existing Workflows

The existing `build-and-test.yml` workflow remains unchanged and continues to
run on every push/PR for CI purposes (multi-version Go matrix, tests, linting).
The new release workflow is **separate** and only triggers on version tags. This
separation is intentional:

- **CI workflow (`build-and-test.yml`):** Tests across Go 1.22 and 1.23, both
  architectures. Runs on every push and PR. No attestation.
- **Release workflow (`release.yml` + `build-release.yml`):** Builds with a
  single pinned Go version, generates attestations, creates an immutable
  release. Runs only on `v*` tags.

---

## SLSA Level 3 Compliance Checklist

| SLSA v1.0 Requirement | Implementation |
|---|---|
| Build runs on a hosted service | GitHub Actions hosted runners |
| Build definition is external and versioned | `build-release.yml` reusable workflow, versioned in the repo |
| Build is isolated from the caller | Reusable workflow provides job-level isolation; caller cannot inject steps |
| Provenance is signed and non-falsifiable | `actions/attest-build-provenance` generates Sigstore-signed in-toto attestation |
| Provenance identifies the build instructions | Attestation metadata records the reusable workflow ref |
| Provenance is verifiable by consumers | `gh attestation verify` with `--signer-workflow` flag |

---

## Open Questions / Decisions

1. **Go version for releases:** The proposal pins to Go 1.23. Should this track
   the latest stable, or should it be explicitly bumped per release?

2. **Same-repo vs. separate-repo reusable workflow:** For maximum SLSA L3
   assurance, GitHub recommends the reusable workflow live in a _separate_
   repository (e.g., an org-level shared workflows repo). Placing it in the same
   repo still meets L3 requirements per the spec, but a separate repo provides
   stronger organizational guarantees. Is a separate repo desired?

3. **Additional platforms:** Should `linux/arm64` be added as a build target?
   This would be straightforward since CGO is disabled for Linux builds.

4. **Pre-release workflow:** Should there be a separate workflow or convention
   for pre-release/RC tags (e.g., `v1.0.0-rc.1`)?

5. **SBOM generation:** Should the release include a Software Bill of Materials
   (SBOM) alongside the provenance attestation? GitHub supports SBOM generation
   via `actions/dependency-review-action` or `anchore/sbom-action`.
