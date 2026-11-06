---- MODULE Breaker ----
\* Circuit breaker around SPNEGO token acquisition, with concurrent callers.
\*
\* Code (spnego-proxy at 52034ab, gobreaker v2.4.0, gokrb5 v8.4.4):
\*   internal/proxy/circuit_breaker.go  NewCircuitBreakerTokenProvider (50-66):
\*       MaxRequests 1, ReadyToTrip ConsecutiveFailures >= threshold;
\*       GetToken (83-103): p.mu held across the whole
\*       p.cb.Execute(func() { return p.inner.GetToken() })
\*   gobreaker.go  Execute (217-235), beforeRequest (237-252), afterRequest
\*       (254-274), onFailure (288-298), currentState (304-318); each of
\*       beforeRequest and afterRequest runs under cb.mutex, and nothing holds
\*       cb.mutex while the request function runs
\*   internal/proxy/auth_gokrb5.go  GetToken (187-216) holds p.mu for the whole
\*       ticketGrantingClient + InitSecContext, so KDC exchanges are serialised;
\*       its password-rejection latch is omitted from this backend abstraction
\*   internal/proxy/forward.go dialAndAuthUpstream (112-139): one GetToken per
\*       upstream connection, so each concurrent client connection is a caller
\*
\* Scenario: the configured password no longer works and the abstract backend
\* has no cached TGT or password-rejection latch. Every inner GetToken makes
\* one AS exchange that the KDC rejects (a failed pre-authentication, which
\* KDC lockout policies count). This conservatively checks the breaker alone;
\* current gokrb5 instead refuses repeat logins for a rejected fingerprint,
\* as modelled in Renewal.tla. Removing only Execute's mutex cannot reproduce
\* the sabotage KDC failures with that provider and an unchanged password.
\* Time is abstract: TimeoutElapses is the Open -> HalfOpen expiry that
\* currentState applies under cb.mutex once Timeout has passed.
EXTENDS Naturals

CONSTANTS
  K,                 \* concurrent callers (client connections needing a token)
  Calls,             \* GetToken calls each caller makes
  Threshold,         \* -cb-threshold (default 3)
  MaxRequests,       \* gobreaker MaxRequests (the code sets 1)
  SerializeExecute   \* TRUE: the code: a mutex held across the whole cb.Execute
                     \* call (circuit_breaker.go 83-103). FALSE: sabotage, the
                     \* ecd1990 shape without that mutex.

Callers == 1..K
None == 0

VARIABLES
  state,        \* gobreaker state: "closed", "open", "half_open"
  gen,          \* gobreaker generation
  requests,     \* counts.Requests in this generation
  consecFail,   \* counts.ConsecutiveFailures in this generation
  pc,           \* per caller: "idle", "admitted", "in_kdc", "returned", "finished"
  callGen,      \* per caller: generation beforeRequest returned
  made,         \* per caller: GetToken calls made
  innerHolder,  \* caller holding Gokrb5TokenProvider.mu, or None
  execHolder,   \* caller holding the fix's Execute mutex, or None
  badLogins,    \* AS exchanges the KDC rejected
  probes,       \* calls admitted while half-open
  startedOpen   \* an AS exchange started while the breaker was open

vars == <<state, gen, requests, consecFail, pc, callGen, made, innerHolder,
          execHolder, badLogins, probes, startedOpen>>

TypeOK ==
  /\ state \in {"closed", "open", "half_open"}
  /\ pc \in [Callers -> {"idle", "admitted", "in_kdc", "returned", "finished"}]
  /\ innerHolder \in Callers \cup {None}
  /\ execHolder \in Callers \cup {None}

Init ==
  /\ state = "closed"
  /\ gen = 0
  /\ requests = 0
  /\ consecFail = 0
  /\ pc = [c \in Callers |-> "idle"]
  /\ callGen = [c \in Callers |-> 0]
  /\ made = [c \in Callers |-> 0]
  /\ innerHolder = None
  /\ execHolder = None
  /\ badLogins = 0
  /\ probes = 0
  /\ startedOpen = FALSE

\* setState / toNewGeneration: new generation, counts cleared.
NewGeneration(s) ==
  /\ state' = s
  /\ gen' = gen + 1
  /\ requests' = 0
  /\ consecFail' = 0

\* beforeRequest, under cb.mutex. Open rejects with ErrOpenState; half-open
\* with MaxRequests already admitted rejects with ErrTooManyRequests.
CallerRejected(c) ==
  /\ pc[c] = "idle"
  /\ made[c] < Calls
  /\ SerializeExecute => execHolder = None
  /\ \/ state = "open"
     \/ state = "half_open" /\ requests >= MaxRequests
  /\ made' = [made EXCEPT ![c] = @ + 1]
  /\ pc' = [pc EXCEPT ![c] = IF made[c] + 1 = Calls THEN "finished" ELSE "idle"]
  /\ UNCHANGED <<state, gen, requests, consecFail, callGen, innerHolder, execHolder,
                 badLogins, probes, startedOpen>>

CallerAdmitted(c) ==
  /\ pc[c] = "idle"
  /\ made[c] < Calls
  /\ SerializeExecute => execHolder = None
  /\ \/ state = "closed"
     \/ state = "half_open" /\ requests < MaxRequests
  /\ requests' = requests + 1
  /\ probes' = IF state = "half_open" THEN probes + 1 ELSE probes
  /\ callGen' = [callGen EXCEPT ![c] = gen]
  /\ pc' = [pc EXCEPT ![c] = "admitted"]
  /\ execHolder' = IF SerializeExecute THEN c ELSE execHolder
  /\ UNCHANGED <<state, gen, consecFail, made, innerHolder, badLogins, startedOpen>>

\* Abstract backend: take its mutex and send an AS-REQ that the KDC rejects,
\* without a cached TGT or a password-rejection latch.
InnerSendsLogin(c) ==
  /\ pc[c] = "admitted"
  /\ innerHolder = None
  /\ innerHolder' = c
  /\ pc' = [pc EXCEPT ![c] = "in_kdc"]
  /\ badLogins' = badLogins + 1
  /\ startedOpen' = (startedOpen \/ state = "open")
  /\ UNCHANGED <<state, gen, requests, consecFail, callGen, made, execHolder, probes>>

\* The CredentialError returns and p.mu is released.
InnerReturnsError(c) ==
  /\ pc[c] = "in_kdc"
  /\ innerHolder' = None
  /\ pc' = [pc EXCEPT ![c] = "returned"]
  /\ UNCHANGED <<state, gen, requests, consecFail, callGen, made, execHolder,
                 badLogins, probes, startedOpen>>

\* afterRequest, under cb.mutex: a result from an older generation is ignored;
\* otherwise onFailure counts it (closed) or reopens (half-open).
AfterRequest(c) ==
  /\ pc[c] = "returned"
  /\ IF callGen[c] # gen
       THEN UNCHANGED <<state, gen, requests, consecFail>>
       ELSE IF state = "half_open"
         THEN NewGeneration("open")
         ELSE IF consecFail + 1 >= Threshold
           THEN NewGeneration("open")
           ELSE /\ consecFail' = consecFail + 1
                /\ UNCHANGED <<state, gen, requests>>
  /\ made' = [made EXCEPT ![c] = @ + 1]
  /\ pc' = [pc EXCEPT ![c] = IF made[c] + 1 = Calls THEN "finished" ELSE "idle"]
  /\ execHolder' = IF SerializeExecute THEN None ELSE execHolder
  /\ UNCHANGED <<callGen, innerHolder, badLogins, probes, startedOpen>>

\* currentState: Open past its expiry becomes HalfOpen.
TimeoutElapses ==
  /\ state = "open"
  /\ NewGeneration("half_open")
  /\ UNCHANGED <<pc, callGen, made, innerHolder, execHolder, badLogins, probes, startedOpen>>

Done ==
  /\ \A c \in Callers : pc[c] = "finished"
  /\ UNCHANGED vars

Next ==
  \/ \E c \in Callers :
       CallerRejected(c) \/ CallerAdmitted(c) \/ InnerSendsLogin(c)
         \/ InnerReturnsError(c) \/ AfterRequest(c)
  \/ TimeoutElapses
  \/ Done

Spec == Init /\ [][Next]_vars

\* ---- Promises (circuit_breaker.go 27-29 and 39-43).

\* The KDC sees at most Threshold rejected logins, plus one per half-open probe.
\* Breaking it: a burst of client connections makes more failed logins than the
\* breaker allows, which counts towards account lockout.
KDCFailuresBounded == badLogins <= Threshold + probes

\* No login reaches the KDC while the breaker is open.
NoLoginWhileOpen == ~startedOpen

\* While half-open, a single probe is let through.
SingleProbe == state = "half_open" => requests <= 1
====
