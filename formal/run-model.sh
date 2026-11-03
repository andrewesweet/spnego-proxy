#!/bin/sh
# Run the TLA+ model checks of spnego-proxy's state machines, and compare each
# config's verdict with formal/expected.txt.
#
#   formal/run-model.sh [MODEL|all] [OUT_ROOT]
#
# MODEL is a folder name under formal/ (m1-relay-keepalive and so on), or a
# path to any folder that holds one *.tla, one or more *.cfg and an optional
# view.mjs. With no argument, or "all", every folder named m* under formal/
# runs. Each config's report.md, chart.mmd and log land in OUT_ROOT/<config>/;
# OUT_ROOT defaults to ${TMPDIR:-/tmp}/spnego-formal-runs/<UTC time>, so a run
# never overwrites an earlier one and never writes into the repository.
#
# The check runs through the pstack /statechart command. Set STATECHART to that
# command when it is neither on PATH nor at the pstack checkout path. The
# command runs on Node 22.18 to 22.x or 23.6 or later, and installs TLC 1.7.4
# with Java 25 (temurin-25) through mise on its first run.
#
# Exit status: 0 when every config ran and matched expected.txt, 1 when a
# config's verdict differs from expected.txt, 2 when the statechart command
# reported an error for any config.
set -u
here=$(cd "$(dirname "$0")" && pwd -P)

sc=${STATECHART:-}
if [ -z "$sc" ]; then
  if command -v statechart >/dev/null 2>&1; then
    sc=$(command -v statechart)
  else
    sc=$HOME/ghq/github.com/cursor/plugins/pstack/skills/statechart/scripts/statechart
  fi
fi
if [ ! -x "$sc" ]; then
  echo "run-model.sh: no statechart command at $sc; set STATECHART to it." >&2
  exit 2
fi

arg=${1:-all}
dirs=
if [ "$arg" = all ]; then
  for d in "$here"/m*/; do
    [ -d "$d" ] && dirs="$dirs $d"
  done
elif [ -d "$arg" ]; then
  dirs=$arg
elif [ -d "$here/$arg" ]; then
  dirs=$here/$arg
else
  echo "run-model.sh: no model folder $arg; one of:" >&2
  for d in "$here"/m*/; do
    [ -d "$d" ] && echo "  $(basename "$d")" >&2
  done
  exit 2
fi
if [ -z "$dirs" ]; then
  echo "run-model.sh: no model folders under $here" >&2
  exit 2
fi

out=${2:-${TMPDIR:-/tmp}/spnego-formal-runs/$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out"
rc=0
for dir in $dirs; do
  model=$(basename "$dir")
  spec=
  for f in "$dir"/*.tla; do
    [ -f "$f" ] && spec=$f && break
  done
  view=
  [ -f "$dir/view.mjs" ] && view="--view $dir/view.mjs"
  echo "$model"
  for cfg in "$dir"/*.cfg; do
    name=$(basename "$cfg" .cfg)
    # shellcheck disable=SC2086
    "$sc" "$spec" --config "$cfg" $view --out "$out/$name" >"$out/$name.log" 2>&1
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
