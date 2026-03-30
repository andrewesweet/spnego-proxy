// interpose_multi_null_cred.c — DYLD interposer that replaces
// gss_iter_creds_f with a version that calls the callback THREE times
// with NULL credential handles, simulating multiple SSO Extension-managed
// credentials (e.g., multi-realm environments).
//
// Build: clang -dynamiclib -framework GSS -o interpose_multi_null_cred.dylib
// interpose_multi_null_cred.c This is ONLY for testing; it is not compiled into
// the production binary.

#include <GSS/GSS.h>

static const gss_OID_desc krb5_oid = {
    9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};

static OM_uint32 interposed_gss_iter_creds_f(
    OM_uint32 *minor_status, OM_uint32 flags, gss_const_OID mech, void *userctx,
    void (*useriter)(void *, gss_OID, gss_cred_id_t)) {
  (void)flags;
  (void)mech;
  *minor_status = 0;
  // Simulate three NULL credentials from different SSO-managed realms.
  useriter(userctx, (gss_OID)&krb5_oid, GSS_C_NO_CREDENTIAL);
  useriter(userctx, (gss_OID)&krb5_oid, GSS_C_NO_CREDENTIAL);
  useriter(userctx, (gss_OID)&krb5_oid, GSS_C_NO_CREDENTIAL);
  return GSS_S_COMPLETE;
}

__attribute__((used)) static struct {
  const void *replacement;
  const void *replacee;
} interpose_tuple __attribute__((section("__DATA,__interpose"))) = {
    (const void *)&interposed_gss_iter_creds_f,
    (const void *)&gss_iter_creds_f,
};
