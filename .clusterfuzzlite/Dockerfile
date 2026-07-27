# ClusterFuzzLite build environment for spnego-proxy.
#
# Pinned by digest for supply-chain parity with the repo's SHA-pinned GitHub
# Actions. The tag was `latest` at pin time; Dependabot's `docker` ecosystem
# (see .github/dependabot.yml, directory /.clusterfuzzlite) keeps this digest
# current. base-builder-go ships the Go toolchain plus the
# `compile_native_go_fuzzer` helper used by build.sh.
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:d98fd3174e3824f362850e675dc4acab8135dc18a0e1efdfbeaacea7fb0c2dbb

COPY . $SRC/spnego-proxy
WORKDIR $SRC/spnego-proxy

# ClusterFuzzLite/OSS-Fuzz invokes $SRC/build.sh; the repo keeps it under
# .clusterfuzzlite/, so stage it at the expected path.
COPY .clusterfuzzlite/build.sh $SRC/build.sh
