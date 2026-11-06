---- MODULE DirectLoop ----
\* One client connection's keep-alive loop, through the upstream proxy and
\* after a request matched -noproxy.
\*
\* Code (spnego-proxy at 52034ab):
\*   internal/proxy/forward.go  run (218-252): every request goes through
\*       routeRequest (254-283); a request that could not be served on the
\*       connection it arrived on comes back as pending and is routed again.
\*   internal/proxy/direct.go  forwardDirect (99-139) dials the request's host
\*       and binds the loop to it (boundHost, 117); nextDirectRequest (141-179)
\*       checks the bound host before validating (153-157) and reports a
\*       request for another host with reroute set, which ends the loop and
\*       routes that request again; relayDirect (181-218) writes the request
\*       on the bound connection.
\* Hosts are compared after sameHost's canonical form (29-44); the parsing
\* itself is out of scope here (fuzzed separately).
\* The model covers plain-HTTP requests only. nextDirectRequest also answers a
\* CONNECT on a bound direct connection with 400 errMismatchedTarget (165-170);
\* that refusal is not modelled, so a regression in it would not show here. A
\* CONNECT for another host is routed again like any other request (Route).
EXTENDS Naturals, Sequences

CONSTANTS
  Hosts,        \* target hosts
  Bypass,       \* the hosts that match -noproxy
  N,            \* requests the client sends on the connection
  CheckBound,   \* TRUE: the code. FALSE: sabotage, without the bound-host check (153).
  Reroute       \* TRUE: the code: a request for another host ends the direct
                \* loop and goes through routeRequest again. FALSE: sabotage,
                \* the ecd1990 refusal: the request is answered 400
                \* errMismatchedTarget and the loop ends.

Upstream == "upstream"

VARIABLES
  route,     \* "upstream" (run loop), "direct" (forwardDirect loop), "closed"
  bound,     \* host the direct connection is bound to, or "none"
  sent,      \* requests the client has sent
  wire,      \* one <<host, path>> per request written out; path is Upstream
             \* or the host of the direct TCP connection it was written on
  refused    \* requests answered 400 errMismatchedTarget

vars == <<route, bound, sent, wire, refused>>

TypeOK ==
  /\ route \in {"upstream", "direct", "closed"}
  /\ sent \in 0..N
  /\ refused \in 0..N

Init ==
  /\ route = "upstream"
  /\ bound = "none"
  /\ sent = 0
  /\ wire = <<>>
  /\ refused = 0

\* routeNoProxy, then either relayViaUpstream or a new forwardDirect loop.
Route(h) ==
  IF h \in Bypass
    THEN /\ route' = "direct"
         /\ bound' = h
         /\ wire' = Append(wire, <<h, h>>)
    ELSE /\ route' = "upstream"
         /\ bound' = "none"
         /\ wire' = Append(wire, <<h, Upstream>>)

ClientSends(h) ==
  /\ route # "closed"
  /\ sent < N
  /\ sent' = sent + 1
  /\ IF route = "upstream"
       THEN /\ Route(h)
            /\ UNCHANGED refused
       ELSE IF CheckBound /\ h # bound
         THEN IF Reroute
                THEN /\ Route(h)
                     /\ UNCHANGED refused
                ELSE /\ route' = "closed"
                     /\ refused' = refused + 1
                     /\ UNCHANGED <<bound, wire>>
         ELSE /\ wire' = Append(wire, <<h, bound>>)
              /\ UNCHANGED <<route, bound, refused>>

\* Either side ends keep-alive.
ConnectionEnds ==
  /\ route # "closed"
  /\ route' = "closed"
  /\ UNCHANGED <<bound, sent, wire, refused>>

Done ==
  /\ route = "closed" \/ sent = N
  /\ UNCHANGED vars

Next == (\E h \in Hosts : ClientSends(h)) \/ ConnectionEnds \/ Done

Spec == Init /\ [][Next]_vars

\* ---- Promises.

\* A request written on a direct connection is for that connection's host
\* (direct.go 91-95).
BoundHostOnly ==
  \A k \in 1..Len(wire) : wire[k][2] # Upstream => wire[k][2] = wire[k][1]

\* Each request goes where -noproxy says: matching hosts direct, others upstream.
PolicyRouting ==
  \A k \in 1..Len(wire) : (wire[k][1] \in Bypass) <=> (wire[k][2] # Upstream)

\* A request is not refused only because an earlier request on the same client
\* connection went to another host.
MixedHostsServed == refused = 0
====
