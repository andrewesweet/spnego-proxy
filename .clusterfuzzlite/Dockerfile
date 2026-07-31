# ClusterFuzzLite build environment for spnego-proxy.
#
# Pinned by digest for supply-chain parity with the repo's SHA-pinned GitHub
# Actions. The tag was `latest` at pin time; Dependabot's `docker` ecosystem
# (see .github/dependabot.yml, directory /.clusterfuzzlite) keeps this digest
# current. base-builder-go ships the Go toolchain plus the
# `compile_native_go_fuzzer` helper used by build.sh.
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:e5e5ecf4fb18a2f47bf0462c37e35728e8f6023ee4b7ff8bc5f903e6acba46da

COPY . $SRC/spnego-proxy
WORKDIR $SRC/spnego-proxy

# ClusterFuzzLite/OSS-Fuzz invokes $SRC/build.sh; the repo keeps it under
# .clusterfuzzlite/, so stage it at the expected path.
COPY .clusterfuzzlite/build.sh $SRC/build.sh
