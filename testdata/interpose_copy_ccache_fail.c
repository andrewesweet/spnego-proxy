// interpose_copy_ccache_fail.c — DYLD interposer that makes
// gss_krb5_copy_ccache always fail, testing the try_initialize_and_copy
// fallback path within cred_iter_callback.
//
// Build: clang -dynamiclib -framework GSS -o interpose_copy_ccache_fail.dylib
// interpose_copy_ccache_fail.c This is ONLY for testing; it is not compiled
// into the production binary.

#include <GSS/GSS.h>
#include <GSS/gssapi_krb5.h>
#include <Kerberos/krb5.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static OM_uint32 interposed_gss_krb5_copy_ccache(OM_uint32 *minor_status,
                                                 gss_cred_id_t cred,
                                                 krb5_ccache out) {
  (void)cred;
  (void)out;
  *minor_status = 0;
  return GSS_S_FAILURE;
}

#pragma clang diagnostic pop

__attribute__((used)) static struct {
  const void *replacement;
  const void *replacee;
} interpose_tuple __attribute__((section("__DATA,__interpose"))) = {
    (const void *)&interposed_gss_krb5_copy_ccache,
    (const void *)&gss_krb5_copy_ccache,
};
