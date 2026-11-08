// Chart words for Breaker.tla: the breaker as an operator sees it, and whether
// a login is at the KDC.
const vals = (m) => (Array.isArray(m) ? m : Object.values(m ?? {}));

export const title = "SPNEGO token circuit breaker with concurrent callers and a latch-free backend abstraction";

export const state = (v) => ({
  Breaker: { closed: "Closed", open: "Open", half_open: "Half-open" }[v.state],
  KDC: vals(v.pc).includes("in_kdc")
    ? "Failed login in flight"
    : vals(v.pc).includes("admitted")
      ? "Callers queued for the KDC"
      : "No login pending",
});

export const step = (action, from, to) => {
  switch (action) {
    case "CallerAdmitted":
      return "a connection asks for a token and is let through";
    case "CallerRejected":
      return "a connection asks for a token and is rejected";
    case "InnerSendsLogin":
      return "the provider sends a login the KDC rejects";
    case "InnerReturnsError":
      return "the login error returns";
    case "AfterRequest":
      if (to.gen !== from.gen) return "the breaker opens";
      return to.consecFail !== from.consecFail ? "the breaker counts the failure" : "the breaker ignores the late result";
    case "TimeoutElapses":
      return "the open timeout passes";
    case "Done":
      return "every connection has its answer";
    default:
      return action;
  }
};
