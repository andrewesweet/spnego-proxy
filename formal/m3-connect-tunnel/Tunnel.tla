---- MODULE Tunnel ----
\* An established CONNECT tunnel with the -idle-timeout check enabled.
\*
\* Code (spnego-proxy at ecd1990):
\*   internal/proxy/connect.go  idleCopy (37-60): before each src.Read it sets
\*       srcConn's read deadline to now + timeout; dst.Write has no deadline;
\*       a read error (deadline, EOF) ends the copy.
\*     forwardHalf (95-106): defer closeWrite(dst) when the copy ends.
\*     forwardTunnel (110-119): one forwardHalf per direction, wg.Wait for both.
\*   internal/proxy/forward.go  handleClient (144-189): the connections close
\*       after run returns, which is after forwardTunnel returns.
\*   cli.go -idle-timeout help: "idle timeout for CONNECT tunnels; connections
\*       with no data flow are closed after this duration (0 to disable)"
\*
\* Time is abstract. HalfTimesOut(d) is the read deadline of direction d
\* passing while d's source sends nothing. otherActive[d] records whether the
\* other direction moved data since d's current read began, which is when d's
\* deadline was set.
EXTENDS Naturals

CONSTANTS
  C,               \* data chunks each side may send
  ConnectionIdle   \* FALSE: the code (per-direction deadline, no write deadline).
                   \* TRUE: fix direction (a deadline that sees both directions,
                   \* and a write deadline).

Dirs == {"up", "down"}       \* up: client to upstream; down: upstream to client
Other(d) == IF d = "up" THEN "down" ELSE "up"

VARIABLES
  phase,          \* "open", "closed"
  half,           \* per direction: "reading", "writing", "done"
  ended,          \* per direction: why the copy ended: "no", "eof", "idle"
  avail,          \* per direction: chunks the source sent that the half has not read
  sentN,          \* per direction: chunks the source has sent
  srcFin,         \* per direction: the source closed its sending side
  sinkOK,         \* per direction: the sink still reads (FALSE: it stalled for good)
  otherActive,    \* per direction: the other direction moved data during this read
  cutWhileFlowing,\* a read deadline ended a direction, or closed the tunnel,
                  \* while the other direction had moved data in this read window
  timeoutReArms,  \* read deadlines that passed while the other direction was
                  \* active and were re-armed instead of ending anything
                  \* (fix direction only)
  abandoned,      \* the write deadline closed the tunnel while the stalled sink
                  \* still had data in flight or queued
  dropped         \* a side sent data that nothing will read, while the tunnel is open

vars == <<phase, half, ended, avail, sentN, srcFin, sinkOK, otherActive,
         cutWhileFlowing, timeoutReArms, abandoned, dropped>>

TypeOK ==
  /\ phase \in {"open", "closed"}
  /\ half \in [Dirs -> {"reading", "writing", "done"}]
  /\ ended \in [Dirs -> {"no", "eof", "idle"}]
  /\ avail \in [Dirs -> 0..C]
  /\ sentN \in [Dirs -> 0..C]

Init ==
  /\ phase = "open"
  /\ half = [d \in Dirs |-> "reading"]
  /\ ended = [d \in Dirs |-> "no"]
  /\ avail = [d \in Dirs |-> 0]
  /\ sentN = [d \in Dirs |-> 0]
  /\ srcFin = [d \in Dirs |-> FALSE]
  /\ sinkOK = [d \in Dirs |-> TRUE]
  /\ otherActive = [d \in Dirs |-> FALSE]
  /\ cutWhileFlowing = FALSE
  /\ timeoutReArms = 0
  /\ abandoned = FALSE
  /\ dropped = FALSE

\* ---- The two peers (the client application, and the upstream proxy with the
\* origin behind it).

PeerSends(d) ==
  /\ phase = "open"
  /\ ~srcFin[d]
  /\ sentN[d] < C
  /\ sentN' = [sentN EXCEPT ![d] = @ + 1]
  /\ avail' = [avail EXCEPT ![d] = @ + 1]
  /\ dropped' = (dropped \/ half[d] = "done")
  /\ UNCHANGED <<phase, half, ended, srcFin, sinkOK, otherActive, cutWhileFlowing,
                timeoutReArms, abandoned>>

PeerFinishesSending(d) ==
  /\ phase = "open"
  /\ ~srcFin[d]
  /\ srcFin' = [srcFin EXCEPT ![d] = TRUE]
  /\ UNCHANGED <<phase, half, ended, avail, sentN, sinkOK, otherActive,
                cutWhileFlowing, timeoutReArms, abandoned, dropped>>

\* The receiving application stops reading for good (suspended, hung, or a
\* zero TCP window that never opens).
SinkStalls(d) ==
  /\ phase = "open"
  /\ sinkOK[d]
  /\ sinkOK' = [sinkOK EXCEPT ![d] = FALSE]
  /\ UNCHANGED <<phase, half, ended, avail, sentN, srcFin, otherActive,
                cutWhileFlowing, timeoutReArms, abandoned, dropped>>

\* ---- forwardHalf / idleCopy for direction d.

HalfReads(d) ==
  /\ phase = "open"
  /\ half[d] = "reading"
  /\ avail[d] > 0
  /\ avail' = [avail EXCEPT ![d] = @ - 1]
  /\ half' = [half EXCEPT ![d] = "writing"]
  /\ otherActive' = [otherActive EXCEPT ![Other(d)] = TRUE]
  /\ UNCHANGED <<phase, ended, sentN, srcFin, sinkOK, cutWhileFlowing,
                timeoutReArms, abandoned, dropped>>

\* dst.Write returns; the loop sets a fresh read deadline and reads again.
HalfWrites(d) ==
  /\ phase = "open"
  /\ half[d] = "writing"
  /\ sinkOK[d]
  /\ half' = [half EXCEPT ![d] = "reading"]
  /\ otherActive' = [otherActive EXCEPT ![d] = FALSE]
  /\ UNCHANGED <<phase, ended, avail, sentN, srcFin, sinkOK, cutWhileFlowing,
                timeoutReArms, abandoned, dropped>>

\* src.Read returns io.EOF: the copy ends and closeWrite(dst) passes the FIN on.
HalfSeesEOF(d) ==
  /\ phase = "open"
  /\ half[d] = "reading"
  /\ avail[d] = 0
  /\ srcFin[d]
  /\ half' = [half EXCEPT ![d] = "done"]
  /\ ended' = [ended EXCEPT ![d] = "eof"]
  /\ UNCHANGED <<phase, avail, sentN, srcFin, sinkOK, otherActive,
                cutWhileFlowing, timeoutReArms, abandoned, dropped>>

\* src.Read fails with the read deadline. The code ends this half only, and
\* closeWrite(dst) sends a FIN to the sink. The fix re-arms when the other
\* direction moved data, and otherwise closes the whole tunnel.
\*
\* Both ways of reacting to the deadline are recorded, so the promise below is
\* about the deadline itself and not only about the code's way of cutting:
\* timeoutReArms counts the fix's re-arms, and cutWhileFlowing counts every
\* cut. In the fix direction the guard makes the close branch reachable only
\* when the other direction is idle, which is what the promise asks for; the
\* code direction is the config that breaks it.
HalfTimesOut(d) ==
  /\ phase = "open"
  /\ half[d] = "reading"
  /\ avail[d] = 0
  /\ ~srcFin[d]
  /\ IF ~ConnectionIdle
       THEN /\ half' = [half EXCEPT ![d] = "done"]
            /\ ended' = [ended EXCEPT ![d] = "idle"]
            /\ cutWhileFlowing' = (cutWhileFlowing \/ otherActive[d])
            /\ timeoutReArms' = timeoutReArms
            /\ UNCHANGED <<phase, otherActive>>
       ELSE IF otherActive[d]
         THEN /\ otherActive' = [otherActive EXCEPT ![d] = FALSE]
              /\ timeoutReArms' = timeoutReArms + 1
              /\ UNCHANGED <<phase, half, ended, cutWhileFlowing>>
         ELSE /\ phase' = "closed"
              /\ ended' = [x \in Dirs |-> IF half[x] = "done" THEN ended[x] ELSE "idle"]
              /\ timeoutReArms' = timeoutReArms
              /\ UNCHANGED <<half, otherActive, cutWhileFlowing>>
  /\ UNCHANGED <<avail, sentN, srcFin, sinkOK, abandoned, dropped>>

\* Fix direction only: a write deadline ends a write to a stalled sink. The
\* chunk in flight, and any chunk still queued for that direction, is never
\* read, so the model records the loss as abandoned rather than dropped:
\* giving up on a peer that stopped reading is what the write deadline is for,
\* and the promise below covers data a live peer would have received.
WriteTimesOut(d) ==
  /\ ConnectionIdle
  /\ phase = "open"
  /\ half[d] = "writing"
  /\ ~sinkOK[d]
  /\ phase' = "closed"
  /\ ended' = [x \in Dirs |-> IF half[x] = "done" THEN ended[x] ELSE "idle"]
  /\ abandoned' = TRUE
  /\ UNCHANGED <<half, avail, sentN, srcFin, sinkOK, otherActive,
                cutWhileFlowing, timeoutReArms, dropped>>

\* wg.Wait returns in forwardTunnel; handleClient closes both connections.
TunnelCloses ==
  /\ phase = "open"
  /\ \A d \in Dirs : half[d] = "done"
  /\ phase' = "closed"
  /\ UNCHANGED <<half, ended, avail, sentN, srcFin, sinkOK, otherActive,
                cutWhileFlowing, timeoutReArms, abandoned, dropped>>

Done ==
  /\ phase = "closed"
  /\ UNCHANGED vars

Next ==
  \/ \E d \in Dirs :
       \/ PeerSends(d) \/ PeerFinishesSending(d) \/ SinkStalls(d)
       \/ HalfReads(d) \/ HalfWrites(d) \/ HalfSeesEOF(d) \/ HalfTimesOut(d)
       \/ WriteTimesOut(d)
  \/ TunnelCloses
  \/ Done

Spec == Init /\ [][Next]_vars

\* ---- Promises. TLC's NoDeadlock also checks for open tunnels with no enabled
\* step: Done covers each closed tunnel. It does not prove eventual termination.

\* A read deadline never cuts a direction, and never closes the tunnel, while
\* the other direction moved data in this read window. Breaking it: a long
\* one-way transfer (a download where the client sends nothing) loses its
\* other direction at the timeout.
IdleCutOnlyWhenIdle == ~cutWhileFlowing

\* While the tunnel is open, data a side sends is forwarded to a sink that is
\* still reading. Data a stalled sink never read is abandoned by the write
\* deadline instead, which is recorded separately, so a pass cannot claim that
\* such data reached the peer.
NoDataDroppedWhileOpen == ~dropped
====
