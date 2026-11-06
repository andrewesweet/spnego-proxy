---- MODULE Serve ----
\* Shutdown of the accept loop and of the keep-alive connections it started.
\*
\* Code (spnego-proxy at 52034ab):
\*   internal/proxy/server.go  Serve (44-92). The accept goroutine (45-77)
\*       loops on l.Accept(): an error returns when ctx is done and otherwise
\*       logs, waits out an exponential backoff while watching ctx, and
\*       retries; a connection starts wg.Go(handleClientCtx). The main path
\*       waits for ctx.Done(), closes the listener, waits for acceptDone,
\*       then races wg.Wait() against time.After(drainTimeout).
\*   internal/proxy/forward.go  handleClientCtx (152-216) starts a watcher
\*       goroutine that closes the connection at once while it is idle
\*       between requests (beginShutdown, 309-320). readRequest (285-307)
\*       sets the idle flag around the deadline-guarded http.ReadRequest and
\*       discards a request that was read after shutdown began. writeResponse
\*       (422-436) sends Connection: close when shutdown began before the
\*       header was serialized, so a busy connection ends after the response
\*       it is sending.
\*   main.go (81-84): SIGINT or SIGTERM cancels ctx; when Serve returns,
\*       provider.Close() runs and the process ends.
\*
\* Time is abstract, except that the code's urgent step (closing idle
\* connections at shutdown) happens before any step that needs time to pass:
\* a read deadline or the drain timeout.
EXTENDS Naturals

CONSTANTS
  K,              \* client connections
  R,              \* requests each client sends at most
  WaitAcceptDone, \* TRUE: the code (<-acceptDone before wg.Wait). FALSE: sabotage.
  DrainCloses     \* TRUE: the code: at shutdown the proxy closes connections
                  \* idle between requests, and ends each connection after the
                  \* response it is sending. FALSE: sabotage, the ecd1990
                  \* shape: idle connections wait out their read deadlines.

Conns == 1..K
None == 0

VARIABLES
  ctxDone,       \* SIGINT or SIGTERM arrived
  listener,      \* "open", "closed"
  loop,          \* accept goroutine: "accepting", "spawning", "stopped"
  cur,           \* the connection Accept returned, before wg.Go
  phase,         \* Serve: "serving", "closing", "awaiting_loop", "draining", "drained", "forced"
  conn,          \* per connection: "none", "backlog", "accepted", "waiting", "busy", "closed"
  served,        \* per connection: requests read
  wg,            \* WaitGroup counter
  waitStarted,   \* wg.Wait has started
  addAfterWait,  \* wg.Go ran after wg.Wait started
  waitedOnIdle   \* the drain waited for time to pass with no request in flight
                 \* and a connection idle between requests

vars == <<ctxDone, listener, loop, cur, phase, conn, served, wg, waitStarted, addAfterWait, waitedOnIdle>>

Idle(i) == conn[i] = "waiting"
Running == phase \notin {"drained", "forced"}

TypeOK ==
  /\ phase \in {"serving", "closing", "awaiting_loop", "draining", "drained", "forced"}
  /\ loop \in {"accepting", "spawning", "stopped"}
  /\ conn \in [Conns -> {"none", "backlog", "accepted", "waiting", "busy", "closed"}]
  /\ wg \in 0..K

Init ==
  /\ ctxDone = FALSE
  /\ listener = "open"
  /\ loop = "accepting"
  /\ cur = None
  /\ phase = "serving"
  /\ conn = [i \in Conns |-> "none"]
  /\ served = [i \in Conns |-> 0]
  /\ wg = 0
  /\ waitStarted = FALSE
  /\ addAfterWait = FALSE
  /\ waitedOnIdle = FALSE

\* The code's urgent idle-close step is pending.
UrgentPending == DrainCloses /\ ctxDone /\ \E i \in Conns : Idle(i)

\* Effect of a step that needs time to pass.
Timed ==
  waitedOnIdle' = (waitedOnIdle \/
                   (phase = "draining" /\ (\A j \in Conns : conn[j] # "busy")
                                       /\ \E i \in Conns : Idle(i)))

ClientDials(i) ==
  /\ Running
  /\ conn[i] = "none"
  /\ listener = "open"
  /\ conn' = [conn EXCEPT ![i] = "backlog"]
  /\ UNCHANGED <<ctxDone, listener, loop, cur, phase, served, wg, waitStarted, addAfterWait, waitedOnIdle>>

LoopAccepts(i) ==
  /\ Running
  /\ loop = "accepting"
  /\ listener = "open"
  /\ conn[i] = "backlog"
  /\ loop' = "spawning"
  /\ cur' = i
  /\ conn' = [conn EXCEPT ![i] = "accepted"]
  /\ UNCHANGED <<ctxDone, listener, phase, served, wg, waitStarted, addAfterWait, waitedOnIdle>>

\* wg.Go(handleClient); run starts reading the first request.
LoopSpawns ==
  /\ Running
  /\ loop = "spawning"
  /\ wg' = wg + 1
  /\ addAfterWait' = (addAfterWait \/ waitStarted)
  /\ conn' = [conn EXCEPT ![cur] = "waiting"]
  /\ loop' = "accepting"
  /\ cur' = None
  /\ UNCHANGED <<ctxDone, listener, phase, served, waitStarted, waitedOnIdle>>

\* l.Accept fails on the closed listener and ctx is done: close(acceptDone).
LoopStops ==
  /\ Running
  /\ loop = "accepting"
  /\ listener = "closed"
  /\ loop' = "stopped"
  /\ UNCHANGED <<ctxDone, listener, cur, phase, conn, served, wg, waitStarted, addAfterWait, waitedOnIdle>>

Signal ==
  /\ phase = "serving"
  /\ ctxDone' = TRUE
  /\ phase' = "closing"
  /\ UNCHANGED <<listener, loop, cur, conn, served, wg, waitStarted, addAfterWait, waitedOnIdle>>

\* l.Close(); connections still in the accept queue are reset.
CloseListener ==
  /\ phase = "closing"
  /\ listener' = "closed"
  /\ conn' = [i \in Conns |-> IF conn[i] = "backlog" THEN "closed" ELSE conn[i]]
  /\ IF WaitAcceptDone
       THEN /\ phase' = "awaiting_loop"
            /\ UNCHANGED waitStarted
       ELSE /\ phase' = "draining"
            /\ waitStarted' = TRUE
  /\ UNCHANGED <<ctxDone, loop, cur, served, wg, addAfterWait, waitedOnIdle>>

\* <-acceptDone returns and wg.Wait starts.
StartDrain ==
  /\ phase = "awaiting_loop"
  /\ loop = "stopped"
  /\ phase' = "draining"
  /\ waitStarted' = TRUE
  /\ UNCHANGED <<ctxDone, listener, loop, cur, conn, served, wg, addAfterWait, waitedOnIdle>>

\* readRequest returns a request.
ClientSendsRequest(i) ==
  /\ Running
  /\ ~ctxDone
  /\ conn[i] = "waiting"
  /\ served[i] < R
  /\ conn' = [conn EXCEPT ![i] = "busy"]
  /\ served' = [served EXCEPT ![i] = @ + 1]
  /\ UNCHANGED <<ctxDone, listener, loop, cur, phase, wg, waitStarted, addAfterWait, waitedOnIdle>>

\* readRequest read a request after shutdown began and discards it: the
\* context check after http.ReadRequest ends the session without routing or
\* answering it.
ShutdownDiscardsRequest(i) ==
  /\ Running
  /\ conn[i] = "waiting"
  /\ served[i] < R
  /\ ctxDone
  /\ served' = [served EXCEPT ![i] = @ + 1]
  /\ conn' = [conn EXCEPT ![i] = "closed"]
  /\ wg' = wg - 1
  /\ UNCHANGED <<ctxDone, listener, loop, cur, phase, waitStarted, addAfterWait, waitedOnIdle>>

\* The response is relayed. run loops for the next request when both sides keep
\* the connection alive; otherwise handleClient returns.
RequestDone(i) ==
  /\ Running
  /\ conn[i] = "busy"
  /\ \E keep \in BOOLEAN :
       IF keep /\ ~(DrainCloses /\ ctxDone)
         THEN /\ conn' = [conn EXCEPT ![i] = "waiting"]
              /\ UNCHANGED wg
         ELSE /\ conn' = [conn EXCEPT ![i] = "closed"]
              /\ wg' = wg - 1
  /\ UNCHANGED <<ctxDone, listener, loop, cur, phase, served, waitStarted, addAfterWait, waitedOnIdle>>

\* The client closes the connection while run waits for a request.
ClientCloses(i) ==
  /\ Running
  /\ conn[i] = "waiting"
  /\ conn' = [conn EXCEPT ![i] = "closed"]
  /\ wg' = wg - 1
  /\ UNCHANGED <<ctxDone, listener, loop, cur, phase, served, waitStarted, addAfterWait, waitedOnIdle>>

\* The ReadTimeout deadline passes in readRequest.
ReadTimeoutPasses(i) ==
  /\ Running
  /\ conn[i] = "waiting"
  /\ ~UrgentPending
  /\ conn' = [conn EXCEPT ![i] = "closed"]
  /\ wg' = wg - 1
  /\ Timed
  /\ UNCHANGED <<ctxDone, listener, loop, cur, phase, served, waitStarted, addAfterWait>>

\* Fix direction only: shutdown interrupts the read of a connection idle
\* between requests.
CloseIdle(i) ==
  /\ Running
  /\ DrainCloses
  /\ ctxDone
  /\ Idle(i)
  /\ conn' = [conn EXCEPT ![i] = "closed"]
  /\ wg' = wg - 1
  /\ UNCHANGED <<ctxDone, listener, loop, cur, phase, served, waitStarted, addAfterWait, waitedOnIdle>>

Drained ==
  /\ phase = "draining"
  /\ wg = 0
  /\ phase' = "drained"
  /\ UNCHANGED <<ctxDone, listener, loop, cur, conn, served, wg, waitStarted, addAfterWait, waitedOnIdle>>

DrainTimesOut ==
  /\ phase = "draining"
  /\ wg > 0
  /\ ~UrgentPending
  /\ phase' = "forced"
  /\ Timed
  /\ UNCHANGED <<ctxDone, listener, loop, cur, conn, served, wg, waitStarted, addAfterWait>>

\* Serve has returned; the process ends.
Done ==
  /\ ~Running
  /\ UNCHANGED vars

Next ==
  \/ \E i \in Conns :
       \/ ClientDials(i) \/ LoopAccepts(i) \/ ClientSendsRequest(i) \/ RequestDone(i)
       \/ ClientCloses(i) \/ ReadTimeoutPasses(i) \/ CloseIdle(i) \/ ShutdownDiscardsRequest(i)
  \/ LoopSpawns \/ LoopStops \/ Signal \/ CloseListener \/ StartDrain
  \/ Drained \/ DrainTimesOut \/ Done

Spec == Init /\ [][Next]_vars

\* ---- Promises.

\* No wg.Go runs after wg.Wait has started (server.go 41-43).
NoAddAfterWait == ~addAfterWait

\* Shutdown waits only for requests in flight: it never waits for a read
\* deadline because a connection sits idle between requests.
DrainSkipsIdle == ~waitedOnIdle
====
