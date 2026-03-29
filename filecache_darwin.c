// clang-format off
//go:build darwin
// clang-format on

#include "filecache_darwin.h"

#include <GSS/GSS.h>
#include <GSS/gssapi_krb5.h>
#include <Kerberos/krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// gss_krb5_copy_ccache is deprecated in favor of gss_export_cred, but
// gss_export_cred serializes to a buffer rather than writing directly to a
// krb5_ccache. Since we need a FILE: ccache on disk (for gss_init_sec_context
// via gss_krb5_ccache_name), gss_krb5_copy_ccache is the correct API.
// Similarly, krb5_cc_close and krb5_cc_destroy are deprecated but have no
// GSS-API replacements for FILE: cache management.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// Kerberos 5 mechanism OID: 1.2.840.113554.1.2.2
static const gss_OID_desc krb5_mech_oid_desc = {
    9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};

// iter_ctx is passed through gss_iter_creds_f to the callback. It carries the
// destination krb5_ccache and accumulates the result of the best (longest
// lifetime) credential copy.
typedef struct {
  krb5_context krb5_ctx;
  krb5_ccache dest_cc;
  uint32_t best_lifetime;  // longest lifetime seen so far
  int copied;              // 1 if at least one copy succeeded
  int error_code;
  char error_msg[512];
} iter_ctx;

// try_initialize_and_copy attempts to initialize the destination cache with
// the principal from the source credential and then copy. This is the fallback
// path if gss_krb5_copy_ccache requires an already-initialized destination.
static int try_initialize_and_copy(iter_ctx *ctx, gss_cred_id_t cred) {
  OM_uint32 major, minor;
  gss_name_t name = GSS_C_NO_NAME;
  gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;

  // Get the credential's principal name.
  major = gss_inquire_cred(&minor, cred, &name, NULL, NULL, NULL);
  if (GSS_ERROR(major)) {
    return -1;
  }

  // Convert gss_name_t to string for krb5_parse_name.
  major = gss_display_name(&minor, name, &name_buf, NULL);
  gss_release_name(&minor, &name);
  if (GSS_ERROR(major)) {
    return -1;
  }

  // Parse the principal string into a krb5_principal.
  char *principal_str = strndup((const char *)name_buf.value, name_buf.length);
  gss_release_buffer(&minor, &name_buf);
  if (principal_str == NULL) {
    return -1;
  }

  krb5_principal princ = NULL;
  krb5_error_code ret = krb5_parse_name(ctx->krb5_ctx, principal_str, &princ);
  free(principal_str);
  if (ret != 0) {
    return -1;
  }

  // Initialize the destination cache with the principal.
  ret = krb5_cc_initialize(ctx->krb5_ctx, ctx->dest_cc, princ);
  krb5_free_principal(ctx->krb5_ctx, princ);
  if (ret != 0) {
    return -1;
  }

  // Retry the copy now that the cache is initialized.
  major = gss_krb5_copy_ccache(&minor, cred, ctx->dest_cc);
  if (GSS_ERROR(major)) {
    return -1;
  }

  return 0;
}

// cred_iter_callback is invoked by gss_iter_creds_f for each credential
// matching the requested mechanism. The gss_cred_id_t is ONLY valid for the
// duration of this callback — it must not be retained.
static void cred_iter_callback(void *userctx, gss_OID mech,
                               gss_cred_id_t cred) {
  (void)mech;
  iter_ctx *ctx = (iter_ctx *)userctx;

  OM_uint32 major, minor;
  OM_uint32 lifetime = 0;

  // Query the credential's remaining lifetime.
  major = gss_inquire_cred(&minor, cred, NULL, &lifetime, NULL, NULL);
  if (GSS_ERROR(major) || lifetime == 0) {
    return;  // Skip expired or unqueryable credentials.
  }

  // Take the first valid credential. Attempting to overwrite a prior good
  // copy with a longer-lived credential risks corrupting the cache if the
  // second copy fails mid-write. In practice, most systems have a single TGT.
  if (ctx->copied) {
    return;
  }

  // Attempt the copy. gss_krb5_copy_ccache may internally call
  // krb5_cc_initialize on the destination. If it does not (Apple's Heimdal
  // fork), the call will fail and we fall back to manual initialization.
  major = gss_krb5_copy_ccache(&minor, cred, ctx->dest_cc);
  if (GSS_ERROR(major)) {
    // Fallback: manually initialize the destination and retry.
    if (try_initialize_and_copy(ctx, cred) != 0) {
      ctx->error_code = 1;
      snprintf(ctx->error_msg, sizeof(ctx->error_msg),
               "gss_krb5_copy_ccache failed (major=0x%x minor=0x%x)",
               (unsigned)major, (unsigned)minor);
      return;
    }
  }

  // Cap GSS_C_INDEFINITE to avoid overflow in Go time calculations.
  if (lifetime == GSS_C_INDEFINITE) {
    lifetime = 3600;  // Cap at 1 hour.
  }

  ctx->best_lifetime = lifetime;
  ctx->copied = 1;
  ctx->error_code = 0;
  ctx->error_msg[0] = '\0';
}

filecache_result copy_creds_to_file_cache(const char *dest_path) {
  filecache_result result;
  memset(&result, 0, sizeof(result));

  // Initialize a krb5 context for cache operations.
  krb5_context krb5_ctx = NULL;
  krb5_error_code ret = krb5_init_context(&krb5_ctx);
  if (ret != 0) {
    result.error_code = 1;
    snprintf(result.error_msg, sizeof(result.error_msg),
             "krb5_init_context failed: %d", (int)ret);
    return result;
  }

  // Build the "FILE:<path>" cache name and resolve it.
  char ccname[1024];
  int n = snprintf(ccname, sizeof(ccname), "FILE:%s", dest_path);
  if (n < 0 || (size_t)n >= sizeof(ccname)) {
    result.error_code = 1;
    snprintf(result.error_msg, sizeof(result.error_msg), "cache path too long");
    krb5_free_context(krb5_ctx);
    return result;
  }

  krb5_ccache dest_cc = NULL;
  ret = krb5_cc_resolve(krb5_ctx, ccname, &dest_cc);
  if (ret != 0) {
    result.error_code = 1;
    snprintf(result.error_msg, sizeof(result.error_msg),
             "krb5_cc_resolve failed: %d", (int)ret);
    krb5_free_context(krb5_ctx);
    return result;
  }

  // Prepare the iteration context.
  iter_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.krb5_ctx = krb5_ctx;
  ctx.dest_cc = dest_cc;

  // Enumerate all Kerberos credentials. The callback runs synchronously for
  // each credential. We pass the krb5 mechanism OID to filter to Kerberos 5
  // credentials only.
  OM_uint32 minor;
  gss_iter_creds_f(&minor, 0, (gss_OID)&krb5_mech_oid_desc, &ctx,
                   cred_iter_callback);

  // Close the krb5 cache handle (does not destroy the file).
  krb5_cc_close(krb5_ctx, dest_cc);
  krb5_free_context(krb5_ctx);

  if (!ctx.copied) {
    result.error_code = 1;
    if (ctx.error_msg[0] != '\0') {
      // Propagate the copy error.
      memcpy(result.error_msg, ctx.error_msg, sizeof(result.error_msg));
    } else {
      snprintf(result.error_msg, sizeof(result.error_msg),
               "no Kerberos credentials found (check 'klist -l')");
    }
    return result;
  }

  result.lifetime = ctx.best_lifetime;
  return result;
}

int set_default_ccache_name(const char *name) {
  OM_uint32 minor;
  // Pass NULL for old_name to avoid thread-safety issues with the static
  // pointer that old_name returns.
  OM_uint32 major = gss_krb5_ccache_name(&minor, name, NULL);
  return GSS_ERROR(major) ? -1 : 0;
}

int destroy_file_cache(const char *path) {
  // Use krb5_cc_destroy to unlink the file and free krb5 resources.
  // The caller is responsible for zeroing the file contents before calling
  // this function (defense-in-depth).
  krb5_context krb5_ctx = NULL;
  krb5_error_code ret = krb5_init_context(&krb5_ctx);
  if (ret != 0) {
    // Fallback: just unlink directly.
    unlink(path);
    return -1;
  }

  char ccname[1024];
  int n = snprintf(ccname, sizeof(ccname), "FILE:%s", path);
  if (n < 0 || (size_t)n >= sizeof(ccname)) {
    krb5_free_context(krb5_ctx);
    unlink(path);
    return -1;
  }

  krb5_ccache cc = NULL;
  ret = krb5_cc_resolve(krb5_ctx, ccname, &cc);
  if (ret != 0) {
    krb5_free_context(krb5_ctx);
    unlink(path);
    return -1;
  }

  // krb5_cc_destroy unlinks the file. Deprecated but no GSS replacement.
  ret = krb5_cc_destroy(krb5_ctx, cc);
  // cc is freed by krb5_cc_destroy; do not call krb5_cc_close.
  krb5_free_context(krb5_ctx);

  if (ret != 0) {
    unlink(path);
    return -1;
  }
  return 0;
}

#pragma clang diagnostic pop
