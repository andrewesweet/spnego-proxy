// clang-format off
//go:build darwin
// clang-format on

#ifndef FILECACHE_DARWIN_H
#define FILECACHE_DARWIN_H

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

// Error message buffer size for filecache_result.
#define FILECACHE_ERROR_MSG_SIZE 512

// Copy method identifiers for filecache_result.copy_method.
#define FILECACHE_COPY_METHOD_GSS 0
#define FILECACHE_COPY_METHOD_KRB5_DIRECT 1

// filecache_result holds the outcome of a credential cache copy operation.
typedef struct {
  int error_code;                            // 0 on success
  char error_msg[FILECACHE_ERROR_MSG_SIZE];  // error description
  uint32_t lifetime;    // remaining credential lifetime in seconds
  uint8_t copy_method;  // FILECACHE_COPY_METHOD_*
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

// darwin_user_temp_dir returns the per-user temporary directory via
// confstr(_CS_DARWIN_USER_TEMP_DIR). This works even in LaunchDaemon
// contexts where $TMPDIR is not set. Returns NULL on failure; the caller
// must free the returned string.
static inline char *darwin_user_temp_dir(void) {
  size_t len = confstr(_CS_DARWIN_USER_TEMP_DIR, NULL, 0);
  if (len == 0) {
    return NULL;
  }
  char *buf = malloc(len);
  if (buf == NULL) {
    return NULL;
  }
  if (confstr(_CS_DARWIN_USER_TEMP_DIR, buf, len) == 0) {
    free(buf);
    return NULL;
  }
  return buf;
}

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
