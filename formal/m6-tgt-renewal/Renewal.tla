---- MODULE Renewal ----
\* The gokrb5 TGT session behind the circuit breaker, after the configured
\* password stops working (for example, the account password was changed
\* while the proxy still holds the old one).
\*
\* Code (spnego-proxy at 52034ab, gobreaker v2.4.0):
\*   internal/proxy/circuit_breaker.go  GetToken (83-103): p.mu held across
\*       the whole cb.Execute around the inner GetToken.
\*   internal/proxy/auth_gokrb5.go  GetToken (187-216): checkPasswordRejected
\*       (348-370) refuses every login until the password file's content
\*       changes, so a latched provider sends no KDC message at all; then
\*       ticketGrantingClient (218-245) reuses the cached TGT client while
\*       ticketRefreshAt is ahead (tgtRefreshDeadline, 288-296: 5/6 through
\*       the lifetime) and otherwise replaces it with acquireCredential
\*       (247-286): one password ASExchange whose client is destroyed before
\*       the call returns, then a client built from a credential cache, with
\*       no session renewal, so service-ticket acquisition cannot fall back
\*       to a password login.
\*
\* Time is abstract: tgt moves fresh -> last_sixth (past ticketRefreshAt) ->
\* expired; every state past the refresh point makes the next GetToken
\* replace the TGT with one password AS exchange. One caller makes the
\* GetToken calls one at a time, so the Closed-state burst of the Breaker
\* model plays no part here.
EXTENDS Naturals

CONSTANTS
  R,                  \* failed logins the unowned renewal goroutine makes
                      \* (sabotage only; the code starts no goroutine)
  Threshold,          \* -cb-threshold
  Calls,              \* GetToken calls
  ProviderOwnsRefresh \* TRUE: the code: the only password login is the TGT
                      \* replacement inside GetToken. FALSE: sabotage, the
                      \* ecd1990 shape: a renewal goroutine logs in outside
                      \* GetToken and the breaker.

VARIABLES
  tgt,       \* "fresh", "last_sixth", "expired"
  stale,     \* the configured password no longer works
  latched,   \* the KDC rejected this password; the provider refuses logins
  pwChanged, \* the password file's content changed since the latch
  cached,    \* a valid service ticket is cached
  br,        \* breaker: "closed", "open", "half_open"
  fails,     \* breaker ConsecutiveFailures
  made,      \* GetToken calls made
  failedAS,  \* AS exchanges the KDC rejected
  counted,   \* rejected AS exchanges the breaker saw as a failed GetToken
  probes,    \* calls admitted while half-open
  tries      \* failed logins the sabotage goroutine made

vars == <<tgt, stale, latched, pwChanged, cached, br, fails, made, failedAS,
          counted, probes, tries>>

TypeOK ==
  /\ tgt \in {"fresh", "last_sixth", "expired"}
  /\ br \in {"closed", "open", "half_open"}
  /\ made \in 0..Calls
  /\ tries \in 0..R

\* The proxy logged in earlier with a password that worked then.
Init ==
  /\ tgt = "fresh"
  /\ stale = FALSE
  /\ latched = FALSE
  /\ pwChanged = FALSE
  /\ cached = TRUE
  /\ br = "closed"
  /\ fails = 0
  /\ made = 0
  /\ failedAS = 0
  /\ counted = 0
  /\ probes = 0
  /\ tries = 0

PasswordStopsWorking ==
  /\ ~stale
  /\ stale' = TRUE
  /\ UNCHANGED <<tgt, latched, pwChanged, cached, br, fails, made, failedAS,
                 counted, probes, tries>>

\* The operator corrects the password file: the next check reads a new
\* fingerprint and clears the latch (checkPasswordRejected), and the new
\* password works.
PasswordFileChanged ==
  /\ ~pwChanged
  /\ pwChanged' = TRUE
  /\ stale' = FALSE
  /\ UNCHANGED <<tgt, latched, cached, br, fails, made, failedAS, counted,
                 probes, tries>>

\* Time passes: the TGT passes ticketRefreshAt, then expires (and the service
\* ticket with it).
TimePasses ==
  /\ tgt # "expired"
  /\ tgt' = IF tgt = "fresh" THEN "last_sixth" ELSE "expired"
  /\ cached' = IF tgt = "last_sixth" THEN FALSE ELSE cached
  /\ UNCHANGED <<stale, latched, pwChanged, br, fails, made, failedAS,
                 counted, probes, tries>>

\* The service ticket can end before the TGT (it carries the end time of the
\* TGT it was issued under).
TicketExpires ==
  /\ cached
  /\ cached' = FALSE
  /\ UNCHANGED <<tgt, stale, latched, pwChanged, br, fails, made, failedAS,
                 counted, probes, tries>>

\* Sabotage only: the ecd1990 renewal goroutine refreshes outside GetToken
\* and the breaker. With a stale password its login is a rejected AS exchange
\* the breaker never sees.
GoroutineRefreshes ==
  /\ ~ProviderOwnsRefresh
  /\ tgt = "last_sixth"
  /\ tries < R
  /\ IF stale
       THEN /\ failedAS' = failedAS + 1
            /\ tries' = tries + 1
            /\ UNCHANGED tgt
       ELSE /\ tgt' = "fresh"
            /\ tries' = 0
            /\ UNCHANGED failedAS
  /\ UNCHANGED <<stale, latched, pwChanged, cached, br, fails, made, counted,
                 probes>>

\* One GetToken: the breaker's beforeRequest, the provider, afterRequest.
\* The provider's only password login is the TGT replacement: a call while
\* ticketRefreshAt is ahead (tgt = "fresh") is served by the cached client
\* and a TGS exchange, and a latch from an earlier rejection refuses the call
\* before any KDC contact, while the breaker still counts the failed call.
Call ==
  /\ made < Calls
  /\ made' = made + 1
  /\ IF br = "open"
       THEN \* gobreaker rejects with ErrOpenState before the provider runs.
            UNCHANGED <<tgt, stale, latched, pwChanged, cached, br, fails,
                        failedAS, counted, probes, tries>>
       ELSE LET probe     == br = "half_open"
                blocked   == latched /\ ~pwChanged
                needLogin == tgt # "fresh"
                rejected  == ~blocked /\ needLogin /\ stale
                ok        == ~blocked /\ ~rejected
            IN /\ probes' = IF probe THEN probes + 1 ELSE probes
               /\ failedAS' = IF rejected THEN failedAS + 1 ELSE failedAS
               /\ counted' = IF rejected THEN counted + 1 ELSE counted
               /\ pwChanged' = IF rejected THEN FALSE ELSE pwChanged
               /\ latched' = IF rejected
                               THEN TRUE
                               ELSE IF latched /\ pwChanged THEN FALSE ELSE latched
               /\ tgt' = IF ok /\ needLogin THEN "fresh" ELSE tgt
               /\ cached' = IF ok THEN TRUE ELSE cached
               /\ IF ok
                    THEN /\ br' = "closed"
                         /\ fails' = 0
                    ELSE IF probe \/ fails + 1 >= Threshold
                      THEN /\ br' = "open"
                           /\ fails' = 0
                      ELSE /\ br' = br
                           /\ fails' = fails + 1
  /\ UNCHANGED <<stale, tries>>

\* currentState: Open past its timeout becomes HalfOpen.
BreakerTimeout ==
  /\ br = "open"
  /\ br' = "half_open"
  /\ fails' = 0
  /\ UNCHANGED <<tgt, stale, latched, pwChanged, cached, made, failedAS,
                 counted, probes, tries>>

Done ==
  /\ made = Calls
  /\ tgt = "expired"
  /\ UNCHANGED vars

Next ==
  \/ PasswordStopsWorking \/ PasswordFileChanged \/ TimePasses \/ TicketExpires
  \/ GoroutineRefreshes \/ Call \/ BreakerTimeout \/ Done

Spec == Init /\ [][Next]_vars

\* ---- Promises (circuit_breaker.go 27-29 and 39-43, auth_gokrb5.go 348-370).

\* Every password login the KDC rejects is a failed call the breaker counts.
BreakerSeesEveryRejectedLogin == failedAS = counted

\* The KDC sees at most Threshold rejected logins, plus one per half-open probe.
RejectedLoginsBounded == failedAS <= Threshold + probes
====
