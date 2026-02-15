# Build and Release Proposal: SLSA Level 3 with Immutable Releases

## Summary

This proposal introduces a formal build and release mechanism for `spnego-proxy`
using GitHub Actions, targeting **SLSA v1.0 Build Level 3** provenance,
**SBOM generation and attestation**, and **GitHub Immutable Releases** for
supply chain integrity.

All versions follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## Goals

1. **macOS builds for Intel and Apple Silicon** -- `darwin/amd64` and
   `darwin/arm64` with CGO enabled for native GSS-API framework linkage.
2. **SLSA v1.0 Build Level 3** -- Using GitHub-native artifact attestations
   (`actions/attest-build-provenance`) inside a reusable workflow to satisfy the
   non-falsifiability requirement.
3. **SBOM generation and attestation** -- Using `anchore/sbom-action` (Syft) for
   SPDX SBOM generation and `actions/attest-sbom` for signed SBOM attestation.
4. **Immutable releases** -- Leveraging GitHub's immutable release feature so
   that published release assets and tags cannot be modified.
5. **Semantic Versioning 2.0.0** -- Stable releases (`vMAJOR.MINOR.PATCH`) and
   pre-releases (`vMAJOR.MINOR.PATCH-PRERELEASE`) handled by a single workflow.
6. **Verification** -- End users can verify both build provenance and SBOM
   attestations via `gh attestation verify`.

---

## Background

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

### GitHub Immutable Releases

When enabled on a repository, any published release becomes immutable:

- Release assets cannot be added, modified, or deleted after publication.
- The associated Git tag cannot be moved or deleted (permanent reservation).
- A **release attestation** is automatically generated (in-toto release
  predicate with `releaseId`, `databaseId`, and `purl`).

**Critical workflow implication:** Releases must be created as **drafts** first,
assets attached to the draft, and then **published**. Any action that creates and
immediately publishes a release will fail when trying to upload assets afterward.

**Enabling:** Repository Settings > Code security > Supply chain > Immutable
releases (checkbox). Can also be enforced at the organization level.

**Important caveats:**
- Once a tag is associated with an immutable release, it is **permanently
  reserved** -- even after deleting the release and tag. The tag cannot be reused.
- Test the workflow with a pre-release tag before the first real release.

### Semantic Versioning 2.0.0

All releases follow [SemVer 2.0.0](https://semver.org/spec/v2.0.0.html):

- **Stable releases:** `vMAJOR.MINOR.PATCH` (e.g., `v1.0.0`, `v1.2.3`)
- **Pre-releases:** `vMAJOR.MINOR.PATCH-PRERELEASE` (e.g., `v1.0.0-alpha.1`,
  `v1.0.0-beta.2`, `v1.0.0-rc.1`)

Pre-release identifiers use dot-separated alphanumeric segments per the spec.
The convention for this project is:

| Phase | Tag Pattern | Example | GitHub Pre-release Flag |
|-------|-------------|---------|------------------------|
| Alpha | `vX.Y.Z-alpha.N` | `v1.0.0-alpha.1` | Yes |
| Beta | `vX.Y.Z-beta.N` | `v1.0.0-beta.1` | Yes |
| Release Candidate | `vX.Y.Z-rc.N` | `v1.0.0-rc.1` | Yes |
| Stable | `vX.Y.Z` | `v1.0.0` | No |

A single workflow handles both stable and pre-release tags. The workflow detects
whether the tag contains a hyphen (per SemVer 2.0.0 pre-release syntax) and sets
the `prerelease` flag on the GitHub release accordingly.

### SBOM (Software Bill of Materials)

An SBOM lists all components and dependencies in the built software. We generate
SBOMs using [`anchore/sbom-action`](https://github.com/anchore/sbom-action)
(which wraps [Syft](https://github.com/anchore/syft)) and then cryptographically
attest the SBOM against each binary using
[`actions/attest-sbom`](https://github.com/actions/attest-sbom).

This provides two distinct attestation types per binary:
1. **Build provenance** (`actions/attest-build-provenance`) -- _how_ and _where_
   the artifact was built.
2. **SBOM attestation** (`actions/attest-sbom`) -- _what_ the artifact contains.

Sources:
- [GitHub Docs: SLSA v1 Build Level 3 with Reusable Workflows](https://docs.github.com/actions/security-guides/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3)
- [GitHub Docs: Immutable Releases](https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/immutable-releases)
- [GitHub Community Discussion: Immutable Releases](https://github.com/orgs/community/discussions/171210)
- [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
- [`actions/attest-sbom`](https://github.com/actions/attest-sbom)
- [`anchore/sbom-action`](https://github.com/anchore/sbom-action)
- [`softprops/action-gh-release`](https://github.com/softprops/action-gh-release) (v2.5.0+)

---

## Architecture

The design uses **two workflow files** to achieve SLSA Build Level 3:

```
 Tag push (vX.Y.Z or vX.Y.Z-pre.N)
       |
       v
 +-------------------------------+
 |  release.yml (caller)         |  <-- Triggered on v* tag push
 |                               |
 |  1. Calls reusable workflow   |
 |  2. Creates release via       |
 |     softprops/action-gh-release
 |     (draft-then-publish)      |
 |  3. Detects pre-release from  |
 |     SemVer tag format         |
 +----------+--------------------+
            | workflow_call
            v
 +-------------------------------+
 |  build-release.yml            |  <-- Reusable workflow
 |  (reusable)                   |
 |                               |
 |  Job: build-macos             |
 |  +-------------------------+  |
 |  | matrix: [amd64, arm64]  |  |  macOS runner
 |  |  -> go build (CGO=1)    |  |  Builds darwin binaries
 |  |  -> attest provenance   |  |  Signs each binary
 |  |  -> generate SBOM       |  |  SPDX via Syft
 |  |  -> attest SBOM         |  |  Signs SBOM against binary
 |  +-------------------------+  |
 +-------------------------------+
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
actual compilation, SBOM generation, and attestation.

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
      - uses: actions/checkout@v4   # Pin to SHA in implementation

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ inputs.go-version }}

      - name: Build (darwin/${{ matrix.arch }})
        env:
          GOARCH: ${{ matrix.arch }}
          GOOS: darwin
          CGO_ENABLED: "1"
          CC: >-
            ${{ matrix.arch == 'amd64'
              && 'clang -arch x86_64'
              || 'clang -arch arm64' }}
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

      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          path: .
          format: spdx-json
          output-file: spnego-proxy-darwin-${{ matrix.arch }}.sbom.spdx.json
          upload-artifact: false
          upload-release-assets: false

      - name: Attest SBOM
        uses: actions/attest-sbom@v2
        with:
          subject-path: spnego-proxy-darwin-${{ matrix.arch }}
          sbom-path: spnego-proxy-darwin-${{ matrix.arch }}.sbom.spdx.json

      - name: Upload binary
        uses: actions/upload-artifact@v4
        with:
          name: spnego-proxy-darwin-${{ matrix.arch }}
          path: spnego-proxy-darwin-${{ matrix.arch }}

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: spnego-proxy-darwin-${{ matrix.arch }}.sbom.spdx.json
          path: spnego-proxy-darwin-${{ matrix.arch }}.sbom.spdx.json
```

**Design notes:**
- **`-trimpath`** is added to `go build` to strip local filesystem paths from
  the binary, improving reproducibility and avoiding information leakage.
- Each binary gets its **own build provenance attestation and SBOM attestation**,
  so consumers can verify individual platform artifacts.
- The SBOM is generated from the source directory (Go modules) using Syft, in
  SPDX JSON format. The same SBOM content applies to both architectures since
  the dependency tree is identical; however, each binary gets a separate SBOM
  attestation binding the SBOM to that specific binary's digest.
- `upload-artifact: false` and `upload-release-assets: false` are set on
  `anchore/sbom-action` because we handle artifact upload and release asset
  attachment ourselves.
- The workflow accepts `go-version` as an input so the caller can pin the exact
  Go version used for a release.
- Action references should be pinned to full commit SHAs in the actual
  implementation (consistent with existing workflows in this repo).

### File 2: `.github/workflows/release.yml` (Caller Workflow)

This workflow triggers on version tag pushes and orchestrates the release
process. It handles both stable and pre-release tags via SemVer detection.

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
          merge-multiple: true

      - name: Generate checksums
        working-directory: artifacts
        run: shasum -a 256 spnego-proxy-* > checksums-sha256.txt

      - name: Detect pre-release from SemVer tag
        id: semver
        run: |
          TAG="${{ github.ref_name }}"
          # SemVer 2.0.0: pre-release version indicated by hyphen after patch
          if [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-.+ ]]; then
            echo "prerelease=true" >> "$GITHUB_OUTPUT"
          else
            echo "prerelease=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Create release (draft, then publish)
        uses: softprops/action-gh-release@v2
        with:
          tag_name: ${{ github.ref_name }}
          draft: true
          prerelease: ${{ steps.semver.outputs.prerelease == 'true' }}
          generate_release_notes: true
          make_latest: ${{ steps.semver.outputs.prerelease != 'true' }}
          files: |
            artifacts/spnego-proxy-darwin-amd64
            artifacts/spnego-proxy-darwin-arm64
            artifacts/spnego-proxy-darwin-amd64.sbom.spdx.json
            artifacts/spnego-proxy-darwin-arm64.sbom.spdx.json
            artifacts/checksums-sha256.txt

      - name: Publish release (makes it immutable)
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          gh release edit "${{ github.ref_name }}" \
            --repo "${{ github.repository }}" \
            --draft=false
```

**Design notes:**
- **`softprops/action-gh-release@v2`** (v2.5.0+) is used with `draft: true`.
  The [immutable releases incompatibility](https://github.com/softprops/action-gh-release/issues/653)
  was fixed in v2.5.0 via PR #692, which implements draft-then-publish
  internally. We still explicitly create as draft and publish separately to be
  defensive, since the two-step pattern is the documented best practice for
  immutable releases.
- **SemVer detection:** The `semver` step uses a regex to detect whether the tag
  contains a pre-release suffix (hyphen after `MAJOR.MINOR.PATCH`). If so, the
  release is flagged as a pre-release on GitHub, which means it will not appear
  as the "Latest" release.
- **`make_latest`** is set to `true` only for stable releases (no pre-release
  suffix). Pre-releases are never marked as latest.
- **SBOM files** are included as release assets alongside the binaries and
  checksums, giving users direct access to the dependency information.
- **`merge-multiple: true`** on `download-artifact` flattens all artifacts from
  the matrix into a single directory.

---

## Release Assets

Each release will contain the following assets:

| Asset | Description |
|-------|-------------|
| `spnego-proxy-darwin-amd64` | macOS Intel binary |
| `spnego-proxy-darwin-arm64` | macOS Apple Silicon binary |
| `spnego-proxy-darwin-amd64.sbom.spdx.json` | SPDX SBOM for Intel binary |
| `spnego-proxy-darwin-arm64.sbom.spdx.json` | SPDX SBOM for Apple Silicon binary |
| `checksums-sha256.txt` | SHA-256 checksums for all binaries |

Additionally, the following are stored as GitHub attestations (not release
assets, but verifiable via `gh attestation verify`):

| Attestation | Action | Predicate Type |
|-------------|--------|----------------|
| Build provenance (per binary) | `actions/attest-build-provenance` | `https://slsa.dev/provenance/v1` |
| SBOM (per binary) | `actions/attest-sbom` | `https://spdx.dev/Document` |
| Release (whole release) | GitHub Immutable Releases | `https://in-toto.io/attestation/release/v0.1` |

---

## Repository Configuration

### 1. Enable Immutable Releases

Navigate to: **Repository Settings > Code security > Supply chain > Immutable
releases** and enable the checkbox. Can also be enforced at the organization
level.

### 2. Tag Protection

Add a tag protection rule for `v*` tags to prevent unauthorized tag creation.
This complements immutable releases by controlling _who_ can trigger the release
workflow.

### 3. Dependabot

The existing Dependabot configuration already covers `github-actions` updates,
which will keep the action references current. No changes needed.

---

## Verification

End users can verify both provenance and SBOM attestations:

```bash
# Verify build provenance for a binary
gh attestation verify spnego-proxy-darwin-arm64 \
  --repo montag451/spnego-proxy

# Verify with signer workflow pinning (strongest SLSA L3 guarantee)
gh attestation verify spnego-proxy-darwin-arm64 \
  --repo montag451/spnego-proxy \
  --signer-workflow .github/workflows/build-release.yml

# Verify the SBOM attestation
gh attestation verify spnego-proxy-darwin-arm64 \
  --repo montag451/spnego-proxy \
  --predicate-type https://spdx.dev/Document

# Verify the release attestation (generated by immutable releases)
gh attestation verify spnego-proxy-darwin-arm64 \
  --repo montag451/spnego-proxy \
  --predicate-type https://in-toto.io/attestation/release/v0.1
```

---

## Rollout Plan

### Phase 1: Add Workflow Files

1. Create `.github/workflows/build-release.yml` (reusable build workflow).
2. Create `.github/workflows/release.yml` (caller release workflow).
3. Pin all action references to full commit SHAs (matching repo convention).

### Phase 2: Enable Repository Features

1. Enable immutable releases in repository settings.
2. Add tag protection rules for `v*`.

### Phase 3: Test with Pre-release

1. Push a pre-release tag (e.g., `v0.0.1-alpha.1`) to trigger the full pipeline.
2. Verify the draft-then-publish flow works correctly with immutable releases.
3. Verify build provenance and SBOM attestations are generated and verifiable.
4. Verify the release is marked as pre-release (not "Latest").

### Phase 4: First Stable Release

1. Tag the desired commit with the release version (e.g., `v1.0.0`).
2. The workflow triggers automatically, builds both macOS binaries, generates
   SBOMs, attests everything, and publishes an immutable release marked as
   "Latest".

---

## Relationship to Existing Workflows

The existing `build-and-test.yml` workflow remains unchanged and continues to
run on every push/PR for CI purposes (multi-version Go matrix, tests, linting).
The new release workflow is **separate** and only triggers on version tags:

- **CI (`build-and-test.yml`):** Tests across Go 1.22 and 1.23, both
  architectures, plus Linux. Runs on every push and PR. No attestation.
- **Release (`release.yml` + `build-release.yml`):** Builds macOS binaries with
  a single pinned Go version, generates SBOMs, creates attestations, and
  publishes an immutable release. Runs only on `v*` tags.

---

## SLSA Level 3 Compliance Checklist

| SLSA v1.0 Requirement | Implementation |
|---|---|
| Build runs on a hosted service | GitHub Actions hosted runners (macOS) |
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
