// Chart words for Renewal.tla: the gokrb5 TGT session behind the breaker.
export const title = "gokrb5 TGT session and its renewal goroutine, behind the circuit breaker";

const tgtWords = { fresh: "TGT valid", last_sixth: "TGT in its last sixth", expired: "TGT expired" };
const brWords = { closed: "Closed", open: "Open", half_open: "Half-open" };

export const state = (v) => ({
  TGT: tgtWords[v.tgt],
  Password: v.stale ? "Password stale" : "Password works",
  Breaker: brWords[v.br],
});

export const step = (action, from, to) => {
  switch (action) {
    case "PasswordStopsWorking":
      return "the account password changes";
    case "TimePasses":
      return to.tgt === "last_sixth" ? "5/6 of the TGT lifetime passes" : "the TGT expires";
    case "TicketExpires":
      return "the cached service ticket expires";
    case "LoopRefreshes":
      if (to.failedAS > from.failedAS) return "the renewal goroutine logs in with the old password; the KDC rejects it";
      return to.tries === 0 && from.tries > 0 ? "the renewal goroutine logs in again" : "the renewal goroutine refreshes the TGT";
    case "Call":
      if (from.br === "open") return "the open breaker rejects a GetToken call";
      return to.failedAS > from.failedAS ? "a GetToken call logs in with the old password and fails" : "a GetToken call succeeds";
    case "BreakerTimeout":
      return "the breaker timeout passes";
    case "Done":
      return "nothing more happens";
    default:
      return action;
  }
};
