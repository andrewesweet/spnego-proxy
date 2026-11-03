// Chart words for Relay.tla: what a person watching one client connection sees.
const seq = (s) => (Array.isArray(s) ? s : Object.values(s ?? {}));
const owed = (v) => v.sent - v.answered - seq(v.toClient).filter((m) => m.kind === "final").length;

export const title = "Plain-HTTP keep-alive relay through the upstream proxy";

export const state = (v) => {
  switch (v.pc) {
    case "read_request":
      return seq(v.toProxy).length === 0 && owed(v) > 0
        ? "Proxy waits for a request while the client waits for a response"
        : "Proxy waits for the next request";
    case "write_request":
      return "Proxy forwards the request upstream";
    case "read_response":
      return "Proxy waits for the upstream response";
    case "write_response":
      return v.resp.kind === "interim" ? "Proxy relays a 1xx as the answer" : "Proxy relays the final response";
    default:
      if (owed(v) > 0) return "Connection closed with a request unanswered";
      return v.closedOnBody ? "Proxy closed the connection after a response with a body" : "Connection closed, every request answered";
  }
};

export const group = (v) => (v.pc === "closed" ? "end" : v.pc === "read_request" ? "client" : "upstream");
export const colors = { client: "blue", upstream: "teal", end: "tan" };

export const step = (action, from, to) => {
  switch (action) {
    case "ClientSendsRequest":
      return "the client sends a request";
    case "ProxyReadsRequest":
      return "the proxy reads the request";
    case "ProxyStopsWaiting":
      return "the read deadline passes or the client hangs up";
    case "ProxyForwardsRequest":
      return "the proxy writes the request upstream";
    case "ProxyReadsResponse":
      return seq(from.upstream)[0].kind === "interim" ? "the proxy reads a 1xx" : "the proxy reads the final response";
    case "ProxyRelaysResponse":
      return to.pc === "closed"
        ? "the proxy writes it to the client; draining the already-closed body fails, so it closes the connection"
        : "the proxy writes it to the client";
    case "UpstreamSendsInterim":
      return "the upstream sends a 1xx";
    case "UpstreamSendsFinal":
      return seq(to.upstream).at(-1).body ? "the upstream sends the final response with a body" : "the upstream sends the final response without a body";
    case "ClientReadsFinal":
      return "the client reads its final response";
    case "ClientSkipsInterim":
      return "the client skips the 1xx";
    case "Done":
      return "the connection stays closed";
    default:
      return action;
  }
};
