// interpose_null_cred.c — DYLD interposer that replaces gss_iter_creds_f
// with a version that always calls the callback with a NULL credential
// handle, simulating the Apple SSO Extension behavior on affected devices.
//
// Build: clang -dynamiclib -framework GSS -o interpose_null_cred.dylib interpose_null_cred.c
// Usage: DYLD_INSERT_LIBRARIES=./interpose_null_cred.dylib ./your_binary
//
// This is ONLY for testing; it is not compiled into the production binary.

#include <GSS/GSS.h>

// Kerberos 5 mechanism OID: 1.2.840.113554.1.2.2
static const gss_OID_desc krb5_oid = {
    9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};

// Replacement gss_iter_creds_f that simulates the Apple SSO Extension
// behavior: enumerate exactly one credential but pass NULL as the handle.
static OM_uint32 interposed_gss_iter_creds_f(
    OM_uint32 *minor_status, OM_uint32 flags, gss_const_OID mech,
    void *userctx,
    void (*useriter)(void *, gss_OID, gss_cred_id_t)) {
  (void)flags;
  (void)mech;
  *minor_status = 0;
  // Call the callback with NULL credential handle, exactly as the SSO
  // Extension does for unbundled processes.
  useriter(userctx, (gss_OID)&krb5_oid, GSS_C_NO_CREDENTIAL);
  return GSS_S_COMPLETE;
}

// DYLD_INTERPOSE macro — replaces the real gss_iter_creds_f at load time.
// This uses the __DATA,__interpose section recognized by dyld.
__attribute__((used)) static struct {
  const void *replacement;
  const void *replacee;
} interpose_tuple __attribute__((section("__DATA,__interpose"))) = {
    (const void *)&interposed_gss_iter_creds_f,
    (const void *)&gss_iter_creds_f,
};
