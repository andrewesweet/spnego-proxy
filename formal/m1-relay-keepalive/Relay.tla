---- MODULE Relay ----
\* Keep-alive relay of plain-HTTP requests through the upstream proxy.
\*
\* Code (spnego-proxy at ecd1990):
\*   internal/proxy/forward.go     run (197-227), readNextRequest (234-251),
\*                                 relayViaUpstream (281-314), writeResponse (347-353)
\*   internal/proxy/response.go    readUpstreamResponse (148-206), which calls
\*                                 http.ReadResponse exactly once (149)
\*   net/http Response.Write closes resp.Body after sending it, so the
\*       io.Copy(io.Discard, resp.Body) that writeResponse runs next fails with
\*       "http: invalid Read on closed Body" for every response with a body,
\*       and relayViaUpstream returns false on that drain error (305-311).
\*
\* One action is one blocking I/O call of the session goroutine, or one message
\* sent by the client or the upstream. Every request and response here is
\* keep-alive, so connectionWillClose (forward.go 95-100) is always false.
\* Dial, SPNEGO token and header rewriting are folded into ProxyForwardsRequest:
\* they do not change which response the proxy pairs with which request.
\* Each request may receive up to MaxInterim 1xx messages before its final
\* response, so the fixed config reads past a 1xx more than once.
EXTENDS Naturals, Sequences

CONSTANTS
  N,             \* requests the client sends on one connection
  LoopOnInterim, \* FALSE: the code at ecd1990. TRUE: the fix direction, which
                 \* relays each 1xx and keeps reading until a final response.
  BodyEndsConnection \* TRUE: the code at ecd1990 (the drain error after a body).
                     \* FALSE: fix direction, a drain that succeeds once
                     \* resp.Write has sent the whole body.

VARIABLES
  pc,         \* where the session goroutine is
  cur,        \* id of the request the proxy is handling
  resp,       \* the message readUpstreamResponse returned for cur
  toProxy,    \* requests the client has written that the proxy has not read
  sent,       \* requests the client has sent
  answered,   \* final responses the client has read
  toClient,   \* messages the proxy has written that the client has not read
  upReqs,     \* requests the upstream has read and not yet finished answering
  upstream,   \* messages in the upstream connection's read buffer (upstreamReader)
  interims,   \* per request: how many 1xx messages the upstream has sent for it
  closedOnBody \* the proxy closed the connection right after relaying a body

vars == <<pc, cur, resp, toProxy, sent, answered, toClient, upReqs, upstream, interims, closedOnBody>>

Ids == 1..N
\* 1xx messages one request may receive before its final response.
MaxInterim == 2
None == [kind |-> "none", for |-> 0, body |-> FALSE]
Interim(i) == [kind |-> "interim", for |-> i, body |-> FALSE]
Final(i, b) == [kind |-> "final", for |-> i, body |-> b]
Msg == {Interim(i) : i \in Ids} \cup {Final(i, b) : i \in Ids, b \in BOOLEAN}

IsFinal(m) == m.kind = "final"

\* Requests the client sent whose final response it has neither read nor has in
\* flight towards it.
Owed == sent - answered - Len(SelectSeq(toClient, IsFinal))

TypeOK ==
  /\ pc \in {"read_request", "write_request", "read_response", "write_response", "closed"}
  /\ cur \in 0..N
  /\ resp \in Msg \cup {None}
  /\ toProxy \in Seq(Ids)
  /\ sent \in 0..N
  /\ answered \in 0..N
  /\ toClient \in Seq(Msg)
  /\ upReqs \in Seq(Ids)
  /\ upstream \in Seq(Msg)
  /\ interims \in [Ids -> 0..MaxInterim]

Init ==
  /\ pc = "read_request"
  /\ cur = 0
  /\ resp = None
  /\ toProxy = <<>>
  /\ sent = 0
  /\ answered = 0
  /\ toClient = <<>>
  /\ upReqs = <<>>
  /\ upstream = <<>>
  /\ interims = [i \in Ids |-> 0]
  /\ closedOnBody = FALSE

\* ---- Client: an HTTP/1.1 user agent. It may pipeline. As RFC 9110 section 15.2
\* requires, it skips a 1xx and keeps waiting for the final response.

ClientSendsRequest ==
  /\ pc # "closed"
  /\ sent < N
  /\ sent' = sent + 1
  /\ toProxy' = Append(toProxy, sent + 1)
  /\ UNCHANGED <<pc, cur, resp, answered, toClient, upReqs, upstream, interims, closedOnBody>>

ClientSkipsInterim ==
  /\ toClient # <<>>
  /\ Head(toClient).kind = "interim"
  /\ toClient' = Tail(toClient)
  /\ UNCHANGED <<pc, cur, resp, toProxy, sent, answered, upReqs, upstream, interims, closedOnBody>>

ClientReadsFinal ==
  /\ toClient # <<>>
  /\ Head(toClient).kind = "final"
  /\ answered' = answered + 1
  /\ toClient' = Tail(toClient)
  /\ UNCHANGED <<pc, cur, resp, toProxy, sent, upReqs, upstream, interims, closedOnBody>>

\* ---- Session goroutine (ClientSession.run).

\* readNextRequest: http.ReadRequest on the client connection.
ProxyReadsRequest ==
  /\ pc = "read_request"
  /\ toProxy # <<>>
  /\ cur' = Head(toProxy)
  /\ toProxy' = Tail(toProxy)
  /\ pc' = "write_request"
  /\ UNCHANGED <<resp, sent, answered, toClient, upReqs, upstream, interims, closedOnBody>>

\* readNextRequest fails on a later iteration: the ReadTimeout deadline passes,
\* or the client hangs up. run returns and handleClient closes the connection.
ProxyStopsWaiting ==
  /\ pc = "read_request"
  /\ toProxy = <<>>
  /\ pc' = "closed"
  /\ UNCHANGED <<cur, resp, toProxy, sent, answered, toClient, upReqs, upstream, interims, closedOnBody>>

\* relayViaUpstream: dialAndAuthUpstream on first use, then req.WriteProxy.
ProxyForwardsRequest ==
  /\ pc = "write_request"
  /\ upReqs' = Append(upReqs, cur)
  /\ pc' = "read_response"
  /\ UNCHANGED <<cur, resp, toProxy, sent, answered, toClient, upstream, interims, closedOnBody>>

\* readUpstreamResponse: one http.ReadResponse call. It returns whatever message
\* is next in upstreamReader, 1xx included.
ProxyReadsResponse ==
  /\ pc = "read_response"
  /\ upstream # <<>>
  /\ upstream' = Tail(upstream)
  /\ IF LoopOnInterim /\ Head(upstream).kind = "interim"
       THEN /\ toClient' = Append(toClient, Head(upstream))
            /\ UNCHANGED <<pc, resp>>
       ELSE /\ resp' = Head(upstream)
            /\ pc' = "write_response"
            /\ UNCHANGED toClient
  /\ UNCHANGED <<cur, toProxy, sent, answered, upReqs, interims, closedOnBody>>

\* writeResponse, then return !connectionWillClose(req, resp), which is true
\* here unless the body drain failed.
ProxyRelaysResponse ==
  /\ pc = "write_response"
  /\ toClient' = Append(toClient, resp)
  /\ resp' = None
  /\ IF BodyEndsConnection /\ resp.body
       THEN /\ pc' = "closed"
            /\ closedOnBody' = TRUE
       ELSE /\ pc' = "read_request"
            /\ UNCHANGED closedOnBody
  /\ UNCHANGED <<cur, toProxy, sent, answered, upReqs, upstream, interims>>

\* ---- Upstream proxy (and the origin behind it): answers requests in order,
\* with up to MaxInterim 1xx messages (103 Early Hints, 100 Continue) before
\* the final one.

\* UpstreamSendsInterim is bounded so that the read-until-final loop is
\* exercised more than once per request: a real upstream may send several 1xx
\* (103 Early Hints, then 100 Continue) before the final response.
UpstreamSendsInterim ==
  /\ upReqs # <<>>
  /\ interims[Head(upReqs)] < MaxInterim
  /\ upstream' = Append(upstream, Interim(Head(upReqs)))
  /\ interims' = [interims EXCEPT ![Head(upReqs)] = @ + 1]
  /\ UNCHANGED <<pc, cur, resp, toProxy, sent, answered, toClient, upReqs, closedOnBody>>

UpstreamSendsFinal ==
  /\ upReqs # <<>>
  /\ \E b \in BOOLEAN : upstream' = Append(upstream, Final(Head(upReqs), b))
  /\ upReqs' = Tail(upReqs)
  /\ UNCHANGED <<pc, cur, resp, toProxy, sent, answered, toClient, interims, closedOnBody>>

Done ==
  /\ pc = "closed"
  /\ UNCHANGED vars

Next ==
  \/ ClientSendsRequest \/ ClientSkipsInterim \/ ClientReadsFinal
  \/ ProxyReadsRequest \/ ProxyStopsWaiting \/ ProxyForwardsRequest
  \/ ProxyReadsResponse \/ ProxyRelaysResponse
  \/ UpstreamSendsInterim \/ UpstreamSendsFinal
  \/ Done

Spec == Init /\ [][Next]_vars

\* ---- Promises.

\* The proxy closes the client connection only once every request the client
\* sent has its final response. Breaking it: the client's request fails after
\* the ReadTimeout wait.
EveryRequestAnswered == pc = "closed" => Owed = 0

\* readUpstreamResponse(reader, req) returns req's own final response. Breaking
\* it: the proxy relays a 1xx as req's answer, and frames a later message with
\* the wrong request.
ProxyReadsOwnResponse == pc = "write_response" => resp.kind = "final" /\ resp.for = cur

\* The connection stays open for the next request after a response that both
\* sides keep alive (relayViaUpstream's doc: the SPNEGO-authenticated upstream
\* connection is reused). Breaking it: every response with a body costs the
\* client a new connection and the proxy a new upstream connection and token.
KeepAliveKept == ~closedOnBody
====
