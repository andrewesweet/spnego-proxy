// clang-format off
//go:build darwin
// clang-format on

#ifndef FILECACHE_DARWIN_H
#define FILECACHE_DARWIN_H

#include <stdint.h>

// filecache_result holds the outcome of a credential cache copy operation.
typedef struct {
  int error_code;       // 0 on success
  char error_msg[512];  // error description
  uint32_t lifetime;    // remaining credential lifetime in seconds
  uint8_t copy_method;  // 0 = GSS iterator, 1 = krb5 direct copy fallback
} filecache_result;

// copy_creds_to_file_cache enumerates Kerberos credentials via
// gss_iter_creds_f, selects the first valid credential, and copies it to a
// FILE: credential cache at dest_path using gss_krb5_copy_ccache.
//
// The destination cache is created (or overwritten) at dest_path. The caller
// is responsible for creating the parent directory with restrictive
// permissions before calling this function.
//
// On success, error_code is 0 and lifetime contains the remaining credential
// lifetime in seconds. On failure, error_code is non-zero and error_msg
// describes the error.
filecache_result copy_creds_to_file_cache(const char *dest_path);

// set_default_ccache_name sets the process-default credential cache name
// via gss_krb5_ccache_name. This redirects subsequent gss_acquire_cred and
// gss_init_sec_context calls (when using GSS_C_NO_CREDENTIAL) to use the
// specified cache.
//
// Pass NULL to reset to the system default.
// Returns 0 on success, non-zero on failure.
int set_default_ccache_name(const char *name);

// destroy_file_cache removes and deallocates the FILE: credential cache
// at the given path using krb5_cc_destroy. The path must refer to a
// FILE:-type credential cache (i.e., a path on disk, not prefixed with
// "FILE:").
//
// The caller should zero the file contents before calling this function
// (defense-in-depth), since krb5_cc_destroy may only unlink without
// zeroing on some Heimdal implementations.
//
// Returns 0 on success, non-zero on failure.
int destroy_file_cache(const char *path);

#endif
