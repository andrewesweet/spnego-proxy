---- MODULE Renewal ----
\* The gokrb5 TGT session behind the circuit breaker, after the configured
\* password stops working (for example, the account password was changed
\* while the proxy still holds the old one).
\*
\* Code (spnego-proxy at ecd1990, gokrb5 v8.4.4, gobreaker v2.4.0):
\*   internal/proxy/circuit_breaker.go  GetToken (73-90): cb.Execute around
\*       the inner GetToken.
\*   internal/proxy/auth_gokrb5.go  GetToken (118-133): AcquireCred, which
\*       calls AffirmLogin, then InitSecContext, which calls GetServiceTicket.
\*   gokrb5 client/client.go  Login (167-192): an AS exchange with the
\*       password, then addSession, which starts enableAutoSessionRenewal;
\*       AffirmLogin (195-204): Login only when there is no session or it has
\*       expired; realmLogin (207-235): Login for the client's own realm.
\*   gokrb5 client/session.go  enableAutoSessionRenewal (185-216): a goroutine
\*       sleeps 5/6 of the remaining lifetime, calls refreshSession, logs any
\*       error and loops on the same end time; refreshSession (237-249):
\*       renewTGT (a TGS exchange, no password) before renew-till, otherwise
\*       realmLogin; ensureValidSession (252-266): refreshSession when at most
\*       1/6 of the lifetime is left.
\*   gokrb5 client/TGSExchange.go  GetServiceTicket (84-108): the cached
\*       service ticket, otherwise sessionTGT (ensureValidSession) and a TGS
\*       exchange.
\*
\* Time is abstract: tgt moves fresh -> last_sixth -> expired. The goroutine's
\* retries on one end time are spaced 5/6 of the remaining time apart, so
\* about log6(lifetime / exchange time) of them fit before expiry; R stands
\* for that count. One caller makes the GetToken calls one at a time, so the
\* Closed-state burst of the Breaker model plays no part here.
EXTENDS Naturals

CONSTANTS
  RenewTillAhead,     \* renew-till stays ahead of every refresh in this scenario
  R,                  \* failed refreshes the goroutine makes before expiry
  Threshold,          \* -cb-threshold
  Calls,              \* GetToken calls
  ProviderOwnsRefresh \* FALSE: the code. TRUE: fix direction: no password
                      \* login runs outside GetToken and the breaker.

VARIABLES
  tgt,       \* "fresh", "last_sixth", "expired"
  stale,     \* the configured password no longer works
  tries,     \* failed refreshes the goroutine made on this TGT
  cached,    \* a valid service ticket is cached
  br,        \* breaker: "closed", "open", "half_open"
  fails,     \* breaker ConsecutiveFailures
  made,      \* GetToken calls made
  failedAS,  \* AS exchanges the KDC rejected
  counted,   \* rejected AS exchanges the breaker saw as a failed GetToken
  probes     \* calls admitted while half-open

vars == <<tgt, stale, tries, cached, br, fails, made, failedAS, counted, probes>>

TypeOK ==
  /\ tgt \in {"fresh", "last_sixth", "expired"}
  /\ br \in {"closed", "open", "half_open"}
  /\ tries \in 0..R
  /\ made \in 0..Calls

\* The proxy logged in earlier with a password that worked then.
Init ==
  /\ tgt = "fresh"
  /\ stale = FALSE
  /\ tries = 0
  /\ cached = TRUE
  /\ br = "closed"
  /\ fails = 0
  /\ made = 0
  /\ failedAS = 0
  /\ counted = 0
  /\ probes = 0

PasswordStopsWorking ==
  /\ ~stale
  /\ stale' = TRUE
  /\ UNCHANGED <<tgt, tries, cached, br, fails, made, failedAS, counted, probes>>

\* Time passes: the goroutine's timer reaches 5/6 of the lifetime, or the TGT
\* expires (and the service ticket with it).
TimePasses ==
  /\ tgt # "expired"
  /\ tgt' = IF tgt = "fresh" THEN "last_sixth" ELSE "expired"
  /\ cached' = IF tgt = "last_sixth" THEN FALSE ELSE cached
  /\ UNCHANGED <<stale, tries, br, fails, made, failedAS, counted, probes>>

\* The service ticket can end before the TGT (it carries the end time of the
\* TGT it was issued under, which a renewal does not extend).
TicketExpires ==
  /\ cached
  /\ cached' = FALSE
  /\ UNCHANGED <<tgt, stale, tries, br, fails, made, failedAS, counted, probes>>

\* refreshSession in the renewal goroutine: outside GetToken and the breaker.
LoopRefreshes ==
  /\ ~ProviderOwnsRefresh
  /\ tgt = "last_sixth"
  /\ tries < R
  /\ IF RenewTillAhead
       THEN /\ tgt' = "fresh"
            /\ UNCHANGED <<tries, failedAS>>
       ELSE IF stale
         THEN /\ failedAS' = failedAS + 1
              /\ tries' = tries + 1
              /\ UNCHANGED tgt
         ELSE /\ tgt' = "fresh"
              /\ tries' = 0
              /\ UNCHANGED failedAS
  /\ UNCHANGED <<stale, cached, br, fails, made, counted, probes>>

\* One GetToken: beforeRequest, the inner provider under p.mu, afterRequest.
Call ==
  /\ made < Calls
  /\ made' = made + 1
  /\ IF br = "open"
       THEN UNCHANGED <<tgt, tries, cached, br, fails, failedAS, counted, probes>>
       ELSE LET probe == br = "half_open"
                needLogin == tgt = "expired"
                needRefresh == ~cached /\ tgt = "last_sixth"
                usesPassword == needLogin \/ (needRefresh /\ ~RenewTillAhead)
                ok == ~(usesPassword /\ stale)
            IN /\ probes' = IF probe THEN probes + 1 ELSE probes
               /\ failedAS' = IF ok THEN failedAS ELSE failedAS + 1
               /\ counted' = IF ok THEN counted ELSE counted + 1
               /\ tgt' = IF ok /\ (needLogin \/ needRefresh) THEN "fresh" ELSE tgt
               /\ tries' = IF ok /\ (needLogin \/ needRefresh) THEN 0 ELSE tries
               /\ cached' = ok
               /\ IF ok
                    THEN /\ br' = "closed"
                         /\ fails' = 0
                    ELSE IF probe \/ fails + 1 >= Threshold
                      THEN /\ br' = "open"
                           /\ fails' = 0
                      ELSE /\ br' = br
                           /\ fails' = fails + 1
  /\ UNCHANGED stale

\* currentState: Open past its timeout becomes HalfOpen.
BreakerTimeout ==
  /\ br = "open"
  /\ br' = "half_open"
  /\ fails' = 0
  /\ UNCHANGED <<tgt, stale, tries, cached, made, failedAS, counted, probes>>

Done ==
  /\ made = Calls
  /\ tgt = "expired"
  /\ UNCHANGED vars

Next ==
  \/ PasswordStopsWorking \/ TimePasses \/ TicketExpires \/ LoopRefreshes
  \/ Call \/ BreakerTimeout \/ Done

Spec == Init /\ [][Next]_vars

\* ---- Promises (circuit_breaker.go 26-29 and 36-40).

\* Every password login the KDC rejects is a failed call the breaker counts.
BreakerSeesEveryRejectedLogin == failedAS = counted

\* The KDC sees at most Threshold rejected logins, plus one per half-open probe.
RejectedLoginsBounded == failedAS <= Threshold + probes
====
