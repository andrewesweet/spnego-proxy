// Chart words for Serve.tla: Serve's shutdown and the connections it started.
const seq = (s) => (Array.isArray(s) ? s : Object.values(s ?? {}));

export const title = "Serve: accept loop, keep-alive connections and shutdown";

const serve = {
  serving: "Serving",
  closing: "Signal received",
  awaiting_loop: "Listener closed, waiting for the accept loop",
  draining: "Draining connections",
  drained: "Returned after a full drain",
  forced: "Returned at the drain timeout",
};

const connections = (v) => {
  const c = seq(v.conn);
  const s = seq(v.served);
  if (c.includes("busy")) return "A request in flight";
  if (c.some((x, i) => x === "waiting" && s[i] > 0)) return "A connection idle between requests";
  if (c.includes("waiting") || c.includes("accepted")) return "A new connection, no request yet";
  if (c.includes("backlog")) return "A connection in the accept queue";
  return "No connection open";
};

const loop = (v) => {
  if (v.loop === "spawning") return "Starting a handler";
  if (v.loop === "stopped") return "Stopped";
  return v.listener === "open" ? "Accepting" : "Accept fails on the closed listener";
};

export const state = (v) => ({
  Serve: serve[v.phase],
  "Accept loop": loop(v),
  Connections: connections(v),
});

export const step = (action, from, to) => {
  switch (action) {
    case "ClientDials":
      return "a client connects";
    case "LoopAccepts":
      return "Accept returns the connection";
    case "LoopSpawns":
      return from.waitStarted ? "wg.Go starts a handler after wg.Wait began" : "wg.Go starts a handler";
    case "LoopStops":
      return "the accept loop sees the closed listener and stops";
    case "Signal":
      return "SIGTERM arrives";
    case "CloseListener":
      return "Serve closes the listener";
    case "StartDrain":
      return "Serve starts waiting for the handlers";
    case "ClientSendsRequest":
      return "a client sends a request";
    case "ShutdownDiscardsRequest":
      return "shutdown discards a request that was read after it began";
    case "RequestDone":
      return to.wg === from.wg ? "the response is relayed; the connection stays open" : "the response is relayed; the connection closes";
    case "ClientCloses":
      return "a client closes its connection";
    case "ReadTimeoutPasses":
      return "the read deadline passes on a waiting connection";
    case "CloseIdle":
      return "Serve closes an idle connection";
    case "Drained":
      return "the last handler returns";
    case "DrainTimesOut":
      return "the drain timeout passes";
    case "Done":
      return "the process exits";
    default:
      return action;
  }
};
