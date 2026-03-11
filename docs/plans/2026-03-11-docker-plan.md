# Docker Image Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Publish a multi-arch Docker image to GHCR that reuses release binaries, with linux/arm64 added to the release pipeline.

**Architecture:** The existing `build-release.yml` gains a `build-linux-arm64` job on a native arm64 runner. A new `docker-release.yml` reusable workflow downloads both linux binaries and builds a multi-arch Docker manifest. `release.yml` orchestrates both Docker push and GitHub release in parallel after build.

**Tech Stack:** Docker buildx, GitHub Actions, `gcr.io/distroless/static-debian12:nonroot`, GHCR

**Design doc:** `docs/plans/2026-03-11-docker-design.md`

---

### Task 1: Add linux/arm64 build job to build-release.yml

**Files:**
- Modify: `.github/workflows/build-release.yml` (add job after line 160)

**Step 1: Add `build-linux-arm64` job**

Add the following job at the end of `build-release.yml`, mirroring `build-linux` but targeting arm64 on a native runner:

```yaml
  build-linux-arm64:
    runs-on: ubuntu-latest-arm64
    permissions:
      contents: read
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

      - name: Set up Go
        uses: actions/setup-go@4b73464bb391d4059bd26b0524d20df3927bd417 # v6.3.0
        with:
          go-version-file: .go-version

      - name: Run unit tests
        env:
          CGO_ENABLED: "0"
        run: go test -v -count=1 ./...

      - name: Build (linux/arm64)
        env:
          GOARCH: arm64
          GOOS: linux
          CGO_ENABLED: "0"
        run: >-
          go build -v -trimpath
          -ldflags "-s -w -X main.version=${{ github.ref_name }} -X main.commit=${{ github.sha }}"
          -o spnego-proxy-linux-arm64 .

      - name: Verify binary
        run: file spnego-proxy-linux-arm64

      - name: Create tar.gz archive
        run: |
          mkdir -p staging
          cp spnego-proxy-linux-arm64 staging/spnego-proxy
          cp LICENSE README.md staging/
          tar -czf spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz -C staging .

      - name: Attest build provenance
        uses: actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26 # v4.1.0
        with:
          subject-path: spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz

      - name: Generate SBOM
        uses: anchore/sbom-action@17ae1740179002c89186b61233e0f892c3118b11 # v0.23.0
        with:
          path: .
          format: spdx-json
          output-file: spnego-proxy-linux-arm64.sbom.spdx.json
          upload-artifact: false
          upload-release-assets: false

      - name: Attest SBOM
        uses: actions/attest@59d89421af93a897026c735860bf21b6eb4f7b26 # v4.1.0
        with:
          subject-path: spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz
          sbom-path: spnego-proxy-linux-arm64.sbom.spdx.json

      - name: Upload archive
        uses: actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f # v7.0.0
        with:
          name: spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz
          path: spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz

      - name: Upload SBOM
        uses: actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f # v7.0.0
        with:
          name: spnego-proxy-linux-arm64.sbom.spdx.json
          path: spnego-proxy-linux-arm64.sbom.spdx.json
```

**Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/build-release.yml'))"`
Expected: No output (valid YAML)

**Step 3: Run actionlint**

Run: `actionlint .github/workflows/build-release.yml` (if available) or verify manually that the job structure matches `build-linux`.

**Step 4: Commit**

```bash
git add .github/workflows/build-release.yml
git commit -m "ci: add linux/arm64 build job to release pipeline"
```

---

### Task 2: Update release.yml to include arm64 artifacts

**Files:**
- Modify: `.github/workflows/release.yml:42-81` (checksums and release assets)

**Step 1: Add arm64 artifacts to checksums**

In the "Generate checksums" step (line 44-52), add the arm64 tarball and SBOM:

```yaml
      - name: Generate checksums for all release artifacts
        working-directory: artifacts
        run: |
          shasum -a 256 \
            spnego-proxy_${{ github.ref_name }}_darwin_amd64.tar.gz \
            spnego-proxy_${{ github.ref_name }}_darwin_arm64.tar.gz \
            spnego-proxy_${{ github.ref_name }}_linux_amd64.tar.gz \
            spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz \
            spnego-proxy-darwin-amd64.sbom.spdx.json \
            spnego-proxy-darwin-arm64.sbom.spdx.json \
            spnego-proxy-linux-amd64.sbom.spdx.json \
            spnego-proxy-linux-arm64.sbom.spdx.json \
            > checksums-sha256.txt
```

**Step 2: Add arm64 assets to release**

In the "Create draft release" step (lines 74-81), add the arm64 files:

```yaml
          files: |
            artifacts/spnego-proxy_${{ github.ref_name }}_darwin_amd64.tar.gz
            artifacts/spnego-proxy_${{ github.ref_name }}_darwin_arm64.tar.gz
            artifacts/spnego-proxy_${{ github.ref_name }}_linux_amd64.tar.gz
            artifacts/spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz
            artifacts/spnego-proxy-darwin-amd64.sbom.spdx.json
            artifacts/spnego-proxy-darwin-arm64.sbom.spdx.json
            artifacts/spnego-proxy-linux-amd64.sbom.spdx.json
            artifacts/spnego-proxy-linux-arm64.sbom.spdx.json
            artifacts/checksums-sha256.txt
```

**Step 3: Validate YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`

**Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add linux/arm64 artifacts to release checksums and assets"
```

---

### Task 3: Create the Dockerfile

**Files:**
- Create: `Dockerfile`

**Step 1: Write Dockerfile**

```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot
COPY spnego-proxy /usr/local/bin/spnego-proxy
ENTRYPOINT ["spnego-proxy"]
```

**Step 2: Validate Dockerfile syntax**

Run: `docker build --check .` or just verify visually — it's 3 lines.

**Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat: add Dockerfile for minimal container image"
```

---

### Task 4: Create docker-release.yml workflow

**Files:**
- Create: `.github/workflows/docker-release.yml`

**Step 1: Write the workflow**

```yaml
name: Docker Release

on:
  workflow_call: {}

permissions: {}

jobs:
  docker:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

      - name: Download linux/amd64 binary artifact
        uses: actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3 # v8.0.0
        with:
          name: spnego-proxy_${{ github.ref_name }}_linux_amd64.tar.gz
          path: artifacts/

      - name: Download linux/arm64 binary artifact
        uses: actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3 # v8.0.0
        with:
          name: spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz
          path: artifacts/

      - name: Extract binaries from archives
        run: |
          mkdir -p build/linux-amd64 build/linux-arm64
          tar -xzf artifacts/spnego-proxy_${{ github.ref_name }}_linux_amd64.tar.gz -C build/linux-amd64
          tar -xzf artifacts/spnego-proxy_${{ github.ref_name }}_linux_arm64.tar.gz -C build/linux-arm64

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2 # v3.10.0

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@74a5d142397b4f367a81961eba4e8cd7edddf772 # v3.4.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Detect pre-release from SemVer tag
        id: semver
        env:
          TAG: ${{ github.ref_name }}
        run: |
          if [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-.+ ]]; then
            echo "prerelease=true" >> "$GITHUB_OUTPUT"
          else
            echo "prerelease=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Build and push amd64 image
        uses: docker/build-push-action@263435318d21b8e681c14492fe198571cfb76f00 # v6.18.0
        with:
          context: build/linux-amd64
          file: Dockerfile
          platforms: linux/amd64
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}-amd64
          labels: |
            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}
            org.opencontainers.image.version=${{ github.ref_name }}

      - name: Build and push arm64 image
        uses: docker/build-push-action@263435318d21b8e681c14492fe198571cfb76f00 # v6.18.0
        with:
          context: build/linux-arm64
          file: Dockerfile
          platforms: linux/arm64
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.ref_name }}-arm64
          labels: |
            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}
            org.opencontainers.image.version=${{ github.ref_name }}

      - name: Create and push multi-arch manifest
        env:
          TAG: ${{ github.ref_name }}
          PRERELEASE: ${{ steps.semver.outputs.prerelease }}
        run: |
          REPO="ghcr.io/${{ github.repository }}"

          docker buildx imagetools create \
            --tag "${REPO}:${TAG}" \
            "${REPO}:${TAG}-amd64" \
            "${REPO}:${TAG}-arm64"

          if [[ "$PRERELEASE" == "false" ]]; then
            docker buildx imagetools create \
              --tag "${REPO}:latest" \
              "${REPO}:${TAG}-amd64" \
              "${REPO}:${TAG}-arm64"
          fi
```

**Step 2: Validate YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/docker-release.yml'))"`

**Step 3: Commit**

```bash
git add .github/workflows/docker-release.yml
git commit -m "ci: add Docker release workflow for multi-arch GHCR image"
```

---

### Task 5: Wire docker job into release.yml

**Files:**
- Modify: `.github/workflows/release.yml:10-16` (add docker job)

**Step 1: Add docker job to release.yml**

Add the docker job after the `build` job definition (line 16), before the `release` job:

```yaml
  docker:
    needs: build
    uses: ./.github/workflows/docker-release.yml
    permissions:
      contents: read
      packages: write
```

**Step 2: Validate YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`

**Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: wire Docker release workflow into release pipeline"
```

---

### Task 6: Update README with Docker usage

**Files:**
- Modify: `README.md` (add Docker installation section)

**Step 1: Find the installation section in README**

Read `README.md` and locate the installation/usage section. Add Docker instructions after the Homebrew section (or after the binary download section).

**Step 2: Add Docker section**

Add the following (adjust placement based on README structure):

```markdown
### Docker

```bash
docker run --rm ghcr.io/andrewesweet/spnego-proxy -version
```

For typical usage, pass proxy flags and expose the listening port:

```bash
docker run --rm -p 3128:3128 ghcr.io/andrewesweet/spnego-proxy \
  -upstream proxy.corp.example.com:8080 \
  -addr :3128
```

Multi-arch images are available for `linux/amd64` and `linux/arm64`.
```

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add Docker installation and usage instructions"
```

---

### Task 7: Validate all workflows together

**Step 1: Validate all modified workflow files**

Run:
```bash
python3 -c "
import yaml, glob
for f in glob.glob('.github/workflows/*.yml'):
    yaml.safe_load(open(f))
    print(f'OK: {f}')
"
```
Expected: All files print OK.

**Step 2: Run actionlint if available**

Run: `actionlint` (validates all workflows)

**Step 3: Verify no lint issues**

Run: `markdownlint README.md` (if available) to verify README formatting.

**Step 4: Final review**

Verify the complete orchestration flow in `release.yml`:
- `build` (build-release.yml) produces 5 artifacts: darwin amd64/arm64, linux amd64/arm64 tarballs + SBOMs
- `docker` (docker-release.yml) needs `build`, downloads linux binaries, pushes multi-arch image
- `release` (inline job) needs `build`, creates GitHub release with all tarballs + SBOMs + checksums
