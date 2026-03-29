// clang-format off
//go:build darwin
// clang-format on

#ifndef GSS_DARWIN_H
#define GSS_DARWIN_H

#include <stddef.h>

// gss_token_result holds the output of a GSS-API token acquisition.
typedef struct {
  void *data;      // Token bytes (caller must free via free())
  size_t length;   // Token length in bytes
  int error_code;  // Non-zero on error
  char error_msg[256];
} gss_token_result;

// acquire_spnego_token acquires a SPNEGO token for the given service principal
// name (e.g., "HTTP@proxy.host.com") using the default credential cache.
gss_token_result acquire_spnego_token(const char *spn);

// acquire_spnego_token_no_preflight acquires a SPNEGO token without the
// gss_acquire_cred pre-flight check. It passes GSS_C_NO_CREDENTIAL to
// gss_init_sec_context, letting the framework find credentials via the
// process-default credential cache (set by gss_krb5_ccache_name).
//
// This function uses a relaxed error check: if gss_init_sec_context returns
// GSS_S_BAD_MECH (0x10000) but produces a non-empty output token with a
// valid SPNEGO ASN.1 structure (tag 0x60), the token is accepted. This
// accommodates an Apple GSS.framework quirk where SPNEGO tokens are produced
// successfully despite a GSS_S_BAD_MECH major status when using FILE: caches
// copied from the SSO Extension's API: cache.
gss_token_result acquire_spnego_token_no_preflight(const char *spn);

#endif
