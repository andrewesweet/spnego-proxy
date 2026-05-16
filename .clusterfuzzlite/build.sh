#!/bin/bash -eu
#
# ClusterFuzzLite build script for spnego-proxy.
#
# Compiles the repo's 7 native `testing.F` fuzz targets into libFuzzer
# binaries via OSS-Fuzz's `compile_native_go_fuzzer` helper.
#
# go.mod invariant: `compile_native_go_fuzzer` rewrites native targets through
# the go-118-fuzz-build shim, which requires the shim be importable. The
# `go get` below mutates ONLY the container's throwaway copy of the module;
# the committed repo go.mod/go.sum are never touched, so the
# "no new module dependency / `go mod tidy` no-diff" rule (CONTRIBUTING.md
# § Fuzzing) still holds. Spike B in the migration plan asserts this.

cd "$SRC/spnego-proxy"

# Build-time-only shim (container copy of the module; not the committed repo).
go install github.com/AdamKorcz/go-118-fuzz-build@latest
go get github.com/AdamKorcz/go-118-fuzz-build/testing

# Fuzz targets live in package proxy at internal/proxy (extracted from
# package main in PR #225 so ClusterFuzzLite can import them).
PKG=github.com/andrewesweet/spnego-proxy/internal/proxy

compile_native_go_fuzzer "$PKG" FuzzNoProxyMatch            fuzz_no_proxy_match
compile_native_go_fuzzer "$PKG" FuzzUpstreamResponseFraming fuzz_upstream_response_framing
compile_native_go_fuzzer "$PKG" FuzzConnectPortChain        fuzz_connect_port_chain
compile_native_go_fuzzer "$PKG" FuzzSameHost                fuzz_same_host
compile_native_go_fuzzer "$PKG" FuzzIPAllowlistChain        fuzz_ip_allowlist_chain
compile_native_go_fuzzer "$PKG" FuzzContentLengthValues     fuzz_content_length_values
compile_native_go_fuzzer "$PKG" FuzzHeaderByteValidators    fuzz_header_byte_validators

# Carry the committed Go regression seed into the ClusterFuzzLite corpus so a
# fresh storage repo starts from the known FuzzNoProxyMatch reproducer.
if [ -d internal/proxy/testdata/fuzz/FuzzNoProxyMatch ]; then
  zip -j "$OUT/fuzz_no_proxy_match_seed_corpus.zip" internal/proxy/testdata/fuzz/FuzzNoProxyMatch/*
fi
