# Docker Image Design

## Summary

Publish a Docker image to GitHub Container Registry (`ghcr.io/andrewesweet/spnego-proxy`)
that reuses the exact release binaries from `build-release.yml`. Multi-arch support
for `linux/amd64` and `linux/arm64`.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Base image | `gcr.io/distroless/static-debian12:nonroot` | CA certs, tzdata, non-root by default, ~2MB |
| Build strategy | Reuse release binaries (no rebuild in Docker) | Identical binaries in tarballs and image |
| Workflow | Reusable workflow called from `release.yml` | Natural artifact sharing, no cross-workflow fragility |
| Triggering | `needs: build` in `release.yml` | Runs in parallel with existing release job |
| Multi-arch | `docker buildx` manifest from per-arch binaries | amd64 + arm64 |
| arm64 binary | Native `ubuntu-latest-arm64` runner | Parity with amd64 build approach |
| Registry | `ghcr.io/andrewesweet/spnego-proxy` | GitHub-native, free for public repos |

## Architecture

### Workflow orchestration in `release.yml`

```
build (build-release.yml)
  |-- docker (docker-release.yml)  [needs: build]
  |-- release (existing job)       [needs: build]
```

Both `docker` and `release` run in parallel after `build` completes.

### Dockerfile

Minimal — copies a pre-built binary, no build stage:

```dockerfile
FROM gcr.io/distroless/static-debian12:nonroot
COPY spnego-proxy /usr/local/bin/spnego-proxy
ENTRYPOINT ["spnego-proxy"]
```

- Runs as UID 65534 (nonroot) by default
- Binary injected at CI time from build artifacts

### docker-release.yml

Reusable workflow (`workflow_call`) that:

1. Downloads `linux/amd64` and `linux/arm64` binary artifacts from the build job
2. Uses `docker buildx` to create a multi-arch manifest
3. Pushes to GHCR

Permissions: `packages: write`, `contents: read`.

### Image tags

- `ghcr.io/andrewesweet/spnego-proxy:v1.2.3` — exact version from git tag
- `ghcr.io/andrewesweet/spnego-proxy:latest` — only for non-pre-release tags

### build-release.yml changes

Add `build-linux-arm64` job using `ubuntu-latest-arm64` runner, mirroring
the existing `build-linux` job with `GOARCH=arm64`.

### release.yml changes

- Add `docker` job calling `./.github/workflows/docker-release.yml` with `needs: build`
- Add `linux/arm64` artifacts to release checksums and asset list
- Add `packages: write` permission for the docker job

## Out of scope

- `docker-compose.yml` (not needed for a proxy binary)
- Health check endpoint
- `.dockerignore` (not building in Docker)
