// Chart words for DirectLoop.tla: one client connection's keep-alive loop.
const seq = (s) => (Array.isArray(s) ? s : Object.values(s ?? {}));

export const title = "Keep-alive loop of one client connection with -noproxy (a and b match, c does not)";

export const state = (v) => {
  if (v.route === "upstream") return "Requests go through the upstream proxy";
  if (v.route === "direct") return `Bound to a direct connection to ${v.bound}`;
  return v.refused > 0 ? "Closed after a 400 for another host" : "Closed";
};

export const step = (action, from, to) => {
  switch (action) {
    case "ClientSends": {
      if (to.refused > from.refused) return "the client asks for another host and gets 400 errMismatchedTarget";
      const w = seq(to.wire);
      const [host, path] = seq(w[w.length - 1]);
      return path === "upstream" ? `the client asks for ${host}; the request goes upstream` : `the client asks for ${host}; the request goes on the connection to ${path}`;
    }
    case "ConnectionEnds":
      return "keep-alive ends";
    case "Done":
      return "nothing more is sent";
    default:
      return action;
  }
};
