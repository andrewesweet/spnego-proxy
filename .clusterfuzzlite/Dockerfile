# ClusterFuzzLite build environment for spnego-proxy.
#
# Pinned by digest for supply-chain parity with the repo's SHA-pinned GitHub
# Actions. The tag was `latest` at pin time; Dependabot's `docker` ecosystem
# (see .github/dependabot.yml, directory /.clusterfuzzlite) keeps this digest
# current. base-builder-go ships the Go toolchain plus the
# `compile_native_go_fuzzer` helper used by build.sh.
FROM gcr.io/oss-fuzz-base/base-builder-go@sha256:a6a7b6569fb3dfde907aafcbdd31fbb9e6004def002b108cca7bfaafd39e1a91

COPY . $SRC/spnego-proxy
WORKDIR $SRC/spnego-proxy

# ClusterFuzzLite/OSS-Fuzz invokes $SRC/build.sh; the repo keeps it under
# .clusterfuzzlite/, so stage it at the expected path.
COPY .clusterfuzzlite/build.sh $SRC/build.sh
