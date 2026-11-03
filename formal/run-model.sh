#!/bin/sh
# Run the TLA+ model checks of spnego-proxy's state machines, and compare each
# config's verdict with formal/expected.txt.
#
#   formal/run-model.sh [MODEL|all] [OUT_ROOT]
#
# MODEL is an exact model folder name under formal/ (m1-relay-keepalive and
# so on). With no argument, or "all", every folder named m* under formal/
# runs. OUT_ROOT selects the output directory; see
# .agents/skills/verify-state-machines/SKILL.md for defaults and output layout.
#
# The check runs through the pstack /statechart command. Set STATECHART to that
# command's executable path, or put statechart on PATH. See the skill above
# for toolchain prerequisites.
#
# See the skill above for exit statuses and verdict handling.
set -u
here=$(cd "$(dirname "$0")" && pwd -P)

sc=${STATECHART:-$(command -v statechart 2>/dev/null)}
if [ ! -x "$sc" ]; then
  echo "run-model.sh: statechart unavailable; set STATECHART to an executable path or put statechart on PATH." >&2
  exit 2
fi

arg=${1:-all}
out=${2:-${TMPDIR:-/tmp}/spnego-formal-runs/$(date -u +%Y%m%dT%H%M%SZ)}
set --
for d in "$here"/m*/; do
  [ -d "$d" ] || continue
  if [ "$arg" = all ] || [ "$arg" = "$(basename "$d")" ]; then
    set -- "$@" "$d"
  fi
done
if [ "$#" -eq 0 ]; then
  echo "run-model.sh: no model folder named $arg; use all or an exact model folder name." >&2
  echo "Usage: formal/run-model.sh [MODEL|all] [OUT_ROOT]" >&2
  for d in "$here"/m*/; do
    [ -d "$d" ] && echo "  $(basename "$d")" >&2
  done
  exit 2
fi

mkdir -p "$out"
rc=0
for dir in "$@"; do
  model=$(basename "$dir")
  spec=
  for f in "$dir"/*.tla; do
    [ -f "$f" ] && spec=$f && break
  done
  echo "$model"
  for cfg in "$dir"/*.cfg; do
    name=$(basename "$cfg" .cfg)
    set -- "$spec" --config "$cfg"
    [ -f "$dir/view.mjs" ] && set -- "$@" --view "$dir/view.mjs"
    "$sc" "$@" --out "$out/$name" >"$out/$name.log" 2>&1
    code=$?
    case $code in
      0|1) ;;
      *)
        echo "  $name: statechart error (exit $code), see $out/$name.log"
        [ $rc -lt 2 ] && rc=2
        continue
        ;;
    esac
    breaks=$(sed -n 's/^## \(.*\) breaks$/\1/p' "$out/$name.log" | sort | paste -sd, -)
    unchecked=$(awk '/^## Rules not checked$/{getline; gsub(/[[:space:]]/, ""); print; exit}' \
      "$out/$name.log" | tr ',' '\n' | sort | paste -sd, -)
    [ -z "$breaks" ] && breaks=-
    [ -z "$unchecked" ] && unchecked=-
    actual="breaks=$breaks unchecked=$unchecked"
    want=$(grep "^$model/$name " "$here/expected.txt" | head -n 1 | cut -d' ' -f2-)
    if [ -z "$want" ]; then
      echo "  $name: no line in expected.txt, actual $actual"
      [ $rc -eq 0 ] && rc=1
    elif [ "$actual" = "$want" ]; then
      echo "  $name: ok, $actual"
    else
      echo "  $name: MISMATCH"
      echo "    expected $want"
      echo "    actual   $actual"
      [ $rc -eq 0 ] && rc=1
    fi
  done
done
echo "outputs: $out"
exit $rc
