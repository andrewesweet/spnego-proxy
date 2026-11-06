// Chart words for Renewal.tla: the gokrb5 TGT session behind the breaker.
export const title = "gokrb5 TGT session behind the circuit breaker";

const tgtWords = { fresh: "TGT valid", last_sixth: "TGT past its refresh point", expired: "TGT expired" };
const brWords = { closed: "Closed", open: "Open", half_open: "Half-open" };

export const state = (v) => ({
  TGT: tgtWords[v.tgt],
  Password: v.stale ? "Password stale" : v.pwChanged ? "Password file corrected" : "Password works",
  Logins: v.latched && !v.pwChanged ? "Refused until the password changes" : "Allowed",
  Breaker: brWords[v.br],
});

export const step = (action, from, to) => {
  switch (action) {
    case "PasswordStopsWorking":
      return "the account password changes";
    case "PasswordFileChanged":
      return "the operator corrects the password file";
    case "TimePasses":
      return to.tgt === "last_sixth" ? "5/6 of the TGT lifetime passes" : "the TGT expires";
    case "TicketExpires":
      return "the cached service ticket expires";
    case "GoroutineRefreshes":
      if (to.failedAS > from.failedAS) return "the renewal goroutine logs in with the old password; the KDC rejects it";
      return to.tries === 0 && from.tries > 0
        ? "the renewal goroutine logs in again"
        : "the renewal goroutine gets a fresh TGT";
    case "Call":
      if (from.br === "open") return "the open breaker rejects a GetToken call";
      if (to.failedAS > from.failedAS) return "a GetToken call logs in with the old password; the KDC rejects it and the provider refuses further logins";
      if (from.latched && !from.pwChanged) return "the provider refuses the call; no login is sent";
      if (from.tgt !== "fresh") return "a GetToken call logs in successfully";
      return "a GetToken call succeeds";
    case "BreakerTimeout":
      return "the breaker timeout passes";
    case "Done":
      return "nothing more happens";
    default:
      return action;
  }
};
