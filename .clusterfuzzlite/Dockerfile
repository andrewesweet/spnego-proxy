# ClusterFuzzLite build environment for spnego-proxy.
#
# Pinned by digest for supply-chain parity with the repo's SHA-pinned GitHub
# Actions. The tag was `latest` at pin time; Dependabot's `docker` ecosystem
# (see .github/dependabot.yml, directory /.clusterfuzzlite) keeps this digest
# current. base-builder-go ships the Go toolchain plus the
# `compile_native_go_fuzzer` helper used by build.sh.
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:1dbadefbb28c6bfd796c64d9c2115977deb8f19494533cc5a3b724c3441df23d

COPY . $SRC/spnego-proxy
WORKDIR $SRC/spnego-proxy

# ClusterFuzzLite/OSS-Fuzz invokes $SRC/build.sh; the repo keeps it under
# .clusterfuzzlite/, so stage it at the expected path.
COPY .clusterfuzzlite/build.sh $SRC/build.sh
