// Chart words for Tunnel.tla: each direction of one CONNECT tunnel.
export const title = "CONNECT tunnel with -idle-timeout";

const label = (v, d) => {
  if (v.phase === "closed") return "Tunnel closed";
  if (v.half[d] === "done") return v.ended[d] === "idle" ? "Stopped by the idle timeout" : "Finished, peer closed";
  if (v.half[d] === "writing") return v.sinkOK[d] ? "Passing data on" : "Stuck writing to a stalled reader";
  return "Waiting for data";
};

export const state = (v) => ({
  "Client to upstream": label(v, "up"),
  "Upstream to client": label(v, "down"),
});

// The sender for a direction: client for "up", upstream for "down".
const side = (d) => (d === "up" ? "client" : "upstream");
const receiver = (d) => (d === "up" ? "upstream" : "client");
// The direction whose value under key differs between the two states.
const dirOf = (from, to, key) =>
  ["up", "down"].find((d) => JSON.stringify(from[key][d]) !== JSON.stringify(to[key][d])) ?? "up";

export const step = (action, from, to) => {
  switch (action) {
    case "HalfReads":
      return `the proxy reads data from the ${side(dirOf(from, to, "avail"))}`;
    case "HalfWrites":
      return `the proxy finishes writing to the ${receiver(dirOf(from, to, "half"))}`;
    case "HalfSeesEOF":
      return `the proxy reads end of stream from the ${side(dirOf(from, to, "half"))}`;
    case "HalfTimesOut": {
      if (to.phase === "closed") return "the idle timeout closes the tunnel";
      if (from.half.up !== to.half.up || from.half.down !== to.half.down) {
        const d = dirOf(from, to, "half");
        return `the read deadline for data from the ${side(d)} passes; the proxy stops reading it and sends a FIN to the ${receiver(d)}`;
      }
      return `the read deadline for data from the ${side(dirOf(from, to, "otherActive"))} passes and is set again`;
    }
    case "WriteTimesOut": {
      const d = ["up", "down"].find((x) => from.half[x] === "writing" && !from.sinkOK[x]) ?? "up";
      return `the write deadline for data to the ${receiver(d)} passes`;
    }
    case "TunnelCloses":
      return "both directions end and the proxy closes both connections";
    case "SinkStalls":
      return `the ${receiver(dirOf(from, to, "sinkOK"))} stops reading`;
    case "PeerSends":
      return `the ${side(dirOf(from, to, "sentN"))} sends data`;
    case "PeerFinishesSending":
      return `the ${side(dirOf(from, to, "srcFin"))} finishes sending`;
    case "Done":
      return "the tunnel stays closed";
    default:
      return action;
  }
};
