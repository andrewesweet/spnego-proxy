//go:build darwin

#include <GSS/GSS.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "gss_darwin.h"

static void format_gss_error(OM_uint32 major, OM_uint32 minor, char *buf, size_t buflen) {
    OM_uint32 msg_ctx = 0;
    OM_uint32 min_stat;
    gss_buffer_desc msg_buf;
    int first = 1;
    size_t offset = 0;

    do {
        gss_display_status(&min_stat, major, GSS_C_GSS_CODE, GSS_C_NO_OID, &msg_ctx, &msg_buf);
        if (!first && offset < buflen - 2) {
            buf[offset++] = ';';
            buf[offset++] = ' ';
        }
        size_t to_copy = msg_buf.length < (buflen - offset - 1) ? msg_buf.length : (buflen - offset - 1);
        memcpy(buf + offset, msg_buf.value, to_copy);
        offset += to_copy;
        gss_release_buffer(&min_stat, &msg_buf);
        first = 0;
    } while (msg_ctx != 0 && offset < buflen - 1);

    buf[offset] = '\0';
}

gss_token_result acquire_spnego_token(const char *spn) {
    gss_token_result result;
    memset(&result, 0, sizeof(result));

    OM_uint32 major, minor;
    gss_buffer_desc name_buf;
    gss_name_t server_name = GSS_C_NO_NAME;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;

    // SPNEGO mechanism OID: 1.3.6.1.5.5.2
    gss_OID_desc spnego_oid_desc = { 6, (void *)"\x2b\x06\x01\x05\x05\x02" };
    gss_OID spnego_oid = &spnego_oid_desc;

    // Import server name
    name_buf.value = (void *)spn;
    name_buf.length = strlen(spn);
    major = gss_import_name(&minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE, &server_name);
    if (GSS_ERROR(major)) {
        result.error_code = 1;
        format_gss_error(major, minor, result.error_msg, sizeof(result.error_msg));
        return result;
    }

    // Acquire SPNEGO token using default credentials from the ccache
    major = gss_init_sec_context(
        &minor,
        GSS_C_NO_CREDENTIAL,       // use default creds from kinit/Keychain
        &context,
        server_name,
        spnego_oid,                 // SPNEGO mechanism
        GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG,
        0,                          // default lifetime
        GSS_C_NO_CHANNEL_BINDINGS,
        GSS_C_NO_BUFFER,            // no input token (first call)
        NULL,                       // actual mech type (output)
        &output_token,
        NULL,                       // ret_flags
        NULL                        // time_rec
    );

    if (GSS_ERROR(major)) {
        result.error_code = 1;
        format_gss_error(major, minor, result.error_msg, sizeof(result.error_msg));
        gss_release_name(&minor, &server_name);
        if (context != GSS_C_NO_CONTEXT) {
            gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
        }
        return result;
    }

    // Copy output token to caller-owned memory
    if (output_token.length > 0) {
        result.data = malloc(output_token.length);
        if (result.data != NULL) {
            memcpy(result.data, output_token.value, output_token.length);
            result.length = output_token.length;
        } else {
            result.error_code = 1;
            snprintf(result.error_msg, sizeof(result.error_msg), "failed to allocate memory for token");
        }
    }

    // Cleanup GSS-API resources
    gss_release_buffer(&minor, &output_token);
    gss_release_name(&minor, &server_name);
    if (context != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&minor, &context, GSS_C_NO_BUFFER);
    }

    return result;
}

void free_token_data(void *data) {
    free(data);
}
