// Package proxy implements the SPNEGO/Kerberos HTTP proxy core: client
// request handling, upstream proxy dialing, CONNECT tunnelling, header
// rewriting, NO_PROXY matching, response framing, and Kerberos token
// providers. It is imported by package main, which owns the CLI.
package proxy
