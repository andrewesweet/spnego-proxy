# Phase 2 Empirical Findings: google-auth Credential Validation Behavior

**Date:** 2026-04-05
**Status:** Complete — resolves the N1 gate from v2 review
**Scope:** Python `google-auth` 2.49.1 (the library underlying `gcloud`,
Google Cloud SDKs for Python, and Vertex AI clients)

## Purpose

The v2 adversarial review flagged **N1 (Critical)**: the sentinel-token design
depends on whether target tools validate credentials locally before making
network calls. Three specific concerns were raised for Google tooling:

1. "gcloud SDK validates the ADC access token offline using the token's `exp`
   claim before making any network call."
2. "Google Cloud client libraries call `credentials.token_state()` before
   the first RPC; if the token is not a parseable JWT with a non-expired
   `exp`, they attempt a full re-auth flow."
3. "npm v9+ validates the format of registry tokens before the first
   registry call." (Deferred to a separate experiment.)

Phase 3c of the plan is gated on empirical answers to these questions. This
document reports the results of three experiments targeting the Google
concerns.

## Method

All three experiments run `google-auth` 2.49.1 in-process with HTTP
interception via the `responses` library, observing exactly which endpoints
are contacted and in what order. No mitmproxy or CA injection is required
because we control the transport layer directly. The experiments live at
`/tmp/mitm-spike/experiment_{1b,2,3}_*.py` and are reproducible on any
host with `python3 -m pip install google-auth responses cryptography`.

## Experiment 1b — Authorized User ADC Flow

**Setup:** A fake ADC file of type `authorized_user` containing:
- `client_id`: gcloud's real public client ID (764086051850-*)
- `client_secret`: gcloud's real public client secret
- `refresh_token`: `1//0fFAKEREFRESHTOKEN...` (arbitrary string)

The `refresh_token` is a completely fake opaque string — not base64, not a
JWT, no structural validation possible.

**Steps:**
1. `google.auth.default()` to load the credential
2. `credentials.refresh(request)` to exchange refresh_token for access_token
3. `AuthorizedSession().get("https://cloudresourcemanager.googleapis.com/v1/projects")`

**Observed HTTP calls:**
1. `POST https://oauth2.googleapis.com/token` with `grant_type=refresh_token`
   and the fake refresh_token in the form body
2. `GET https://cloudresourcemanager.googleapis.com/v1/projects` with
   `Authorization: Bearer ya29.FAKE_ACCESS_TOKEN_FROM_PROXY_12345`

**Key observations:**
- `google-auth` did NOT validate the refresh_token format before sending it
- The library accepted any string the token endpoint returned as `access_token`
- The fake access_token `ya29.FAKE_ACCESS_TOKEN_FROM_PROXY_12345` is not a
  JWT (no dots, not base64 segments) and was used verbatim in the
  `Authorization` header
- NO calls to `tokeninfo`, `userinfo`, or any verification endpoint
- The library never examined the token claims, never parsed it as JWT,
  never checked `exp`

**Verdict:** The v2 review concern "validates the ADC access token offline
using the token's `exp` claim" is **false for the authorized_user flow**.
The sentinel model works with plain opaque strings and requires no JWT
structure.

## Experiment 2 — Service Account ADC Flow

**Setup:** A fake service-account ADC file with:
- An **ephemeral RSA-2048 key generated in-process** (never seen by Google)
- `client_email`: `fake-agent@fake-project.iam.gserviceaccount.com`
- All other fields filled with plausible values

**Steps:** Same as Experiment 1b.

**Observed HTTP calls:**
1. `POST https://oauth2.googleapis.com/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` and an
   `assertion` parameter containing a JWT signed with the ephemeral key
2. `GET https://cloudresourcemanager.googleapis.com/v1/projects` with
   `Authorization: Bearer ya29.FAKE_SA_ACCESS_TOKEN`

**JWT assertion contents (decoded):**
```
header:  {"typ": "JWT", "alg": "RS256", "kid": "fake-key-id"}
payload: {
  "iat": 1775403823,
  "exp": 1775407423,
  "iss": "fake-agent@fake-project.iam.gserviceaccount.com",
  "aud": "https://oauth2.googleapis.com/token",
  "scope": "https://www.googleapis.com/auth/cloud-platform"
}
```

**Key observations:**
- `google-auth` signed the assertion with whatever key was in the ADC file,
  without any validation that the key is real or trusted
- The assertion POST would normally fail at Google (the public key for
  `fake-key-id` is not registered against that service account), but the
  proxy intercepts it first
- Once the proxy returns a fake `access_token`, the flow is identical to
  the authorized_user case: the library uses it verbatim

**Verdict:** Service accounts work too. The container holds an **ephemeral
fake private key** that is useless outside the proxy context but satisfies
the library's local API. No real cryptographic material is in the container.

## Experiment 3 — id_token Verification Path

**Setup:** This is the adversarial case. We explicitly exercise
`google.oauth2.id_token.verify_oauth2_token()`, which is documented to
verify JWT signatures against Google's published JWKS.

**Steps:**
1. Generate a local RSA key
2. Sign a fake id_token with claims `iss=https://accounts.google.com`,
   `aud=<client_id>`, valid `iat`/`exp`
3. Build a self-signed X.509 certificate wrapping the local public key
4. Intercept `GET https://www.googleapis.com/oauth2/v1/certs` and return
   `{"fake-kid": "<our cert PEM>"}`
5. Call `id_token.verify_oauth2_token(fake_id_token, request, audience=...)`

**Result:** Verification **succeeds**. The decoded payload matches what we
put in. The library fetched our substituted JWKS, found the matching `kid`,
verified the signature against our cert, and returned the claims as if
they were authentic.

**Three verification cases summarized:**

| Case | Path | Outcome |
|------|------|---------|
| `jwt.decode(verify=False)` | Skips verification entirely | Decoded, no errors |
| `jwt.decode(certs=local_cert)` | Caller supplies certs | Verified against local cert |
| `id_token.verify_oauth2_token()` | Library fetches Google JWKS | Verified against substituted JWKS |

**Verdict:** Even the strict verification path is defeated when the proxy
controls the JWKS endpoint. This is a direct consequence of the MITM
position: if the proxy's CA is trusted by the container, then any URL the
library fetches is under proxy control, including JWKS.

## Resolution of N1

The v2 review said:

> **N1 (Critical).** The sentinel token design breaks for tools that
> validate credentials locally before making any network call. gcloud SDK,
> Google Cloud client libraries, and npm v9+ all do this. A sentinel string
> is not a parseable JWT and will fail immediately. This blocks Phase 3c
> as currently designed.

Based on empirical evidence for `google-auth`:

- **False for authorized_user ADC:** no local validation of refresh_token
  or access_token. Plain strings work.
- **False for service_account ADC:** an ephemeral fake key is sufficient
  to satisfy local signing. The real key never needs to be in the container.
- **False for id_token verification:** the JWKS endpoint is under proxy
  control; substituting the proxy's cert defeats signature verification.

**N1 is resolved for all tested google-auth flows.** Phase 3c can proceed
with the simplest sentinel design: plain opaque strings, no JWT construction
required.

The v3 resolution document proposed signed JWT sentinels as a defensive
measure. The empirical evidence shows this is unnecessary for google-auth.
The design simplifies accordingly:

- **Access tokens:** any opaque string, deterministic per session for
  recognition on outbound
- **Refresh tokens:** any opaque string, intercepted at
  `oauth2.googleapis.com/token`
- **Private keys (service account case):** ephemeral RSA key generated
  per session, never used to sign anything that reaches Google
- **id_token verification:** substitute JWKS at
  `www.googleapis.com/oauth2/v1/certs` with proxy-signed cert

## Remaining Empirical Work

This spike covered Python `google-auth`. The following are NOT yet tested
empirically and should be before full Phase 3c commitment:

1. **gcloud CLI itself** (Go binary) — likely shares transport semantics
   with google-auth-python since gcloud reads the same ADC file format,
   but the verification paths could differ
2. **Node.js `google-auth-library`** — popular via Vertex AI JS clients
3. **Java `google-auth-library-java`** — used by many enterprise workloads
4. **`gh` with fake PAT** — expected trivial (PAT is opaque), but confirm
   `gh auth status` behavior with a fake token
5. **`npm` v9+ token format validation** — the specific concern from N1
6. **`pip` with `--index-url` containing a fake PAT**

**Recommendation:** proceed to Phase 3a (TLS interception core) in parallel
with tests 1–6, which can run against the prototype as it matures. None of
these tests is likely to invalidate the core model; they'd refine which
tools need special-case handling.

## Experiment Scripts

All scripts are reproducible:

- `/tmp/mitm-spike/experiment_1b_adc_proper_mock.py` — authorized_user flow
- `/tmp/mitm-spike/experiment_2_service_account.py` — service_account flow
- `/tmp/mitm-spike/experiment_3_id_token_verification.py` — JWKS substitution

Requirements: `pip install google-auth responses cryptography`

The scripts should be moved into a `test/phase2/` directory in the
agent-proxy repository (or the spnego-proxy repository under a new
subdirectory) when the prototype begins. They serve as regression tests
against future `google-auth` releases that might introduce stricter
local validation.
