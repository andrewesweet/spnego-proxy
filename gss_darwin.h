//go:build darwin

#ifndef GSS_DARWIN_H
#define GSS_DARWIN_H

#include <stddef.h>

// gss_token_result holds the output of a GSS-API token acquisition.
typedef struct {
    void *data;        // Token bytes (caller must free via free_token_data)
    size_t length;     // Token length in bytes
    int error_code;    // Non-zero on error
    char error_msg[256];
} gss_token_result;

// acquire_spnego_token acquires a SPNEGO token for the given service principal
// name (e.g., "HTTP@proxy.host.com") using the default credential cache.
gss_token_result acquire_spnego_token(const char *spn);

// free_token_data frees token data returned by acquire_spnego_token.
void free_token_data(void *data);

#endif
