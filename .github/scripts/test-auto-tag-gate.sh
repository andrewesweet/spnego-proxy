#!/usr/bin/env bash
# Tests for the Auto Tag gating decision.
#
# The gate that decides whether a completed CI run may tag a release lives
# inline in .github/workflows/auto-tag.yml, in the "Verify all CI checks
# passed" step. This script extracts that exact logic (the block between the
# "# --- gating decision" and "# --- end gating decision" markers) and runs
# it against recorded GitHub API JSON, so the shipped logic and the tested
# logic cannot drift.
#
# Run from anywhere:
#
#   .github/scripts/test-auto-tag-gate.sh
#
# Dependencies: bash, jq. Not yet wired into CI; run it locally when
# touching the Auto Tag workflow.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workflow="${script_dir}/../workflows/auto-tag.yml"

# --- extract the shipped gating logic ---------------------------------------

if [ "$(grep -c -- '# --- gating decision' "${workflow}")" -ne 1 ] ||
   [ "$(grep -c -- '# --- end gating decision' "${workflow}")" -ne 1 ]; then
  echo "FAIL: gating decision markers not found exactly once in ${workflow}"
  exit 1
fi

# Leading YAML indentation is irrelevant to bash, so the extracted block is
# sourced as-is.
eval "$(awk '
  /^ *# --- gating decision/ {on = 1; next}
  /^ *# --- end gating decision/ {on = 0}
  on {print}
' "${workflow}")"

command -v decide >/dev/null || { echo "FAIL: decide() did not extract"; exit 1; }

# --- fixtures ----------------------------------------------------------------

# Recorded from
# repos/andrewesweet/spnego-proxy/actions/runs?head_sha=52034ab2f35bd04a7b91f1a044284a234399c688
# (the v1.3.8 changelog commit), reduced to the fields the gate reads; the
# object shape is unchanged. It deliberately includes the Auto Tag and
# Release runs for the same SHA: the gate must ignore unknown workflow names.
recorded_all_success() {
  cat <<'EOF'
[
  {"id": 42167209597, "name": "Auto Tag", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "failure", "event": "workflow_run", "created_at": "2026-11-06T05:14:13Z"},
  {"id": 42167031277, "name": "Lint Workflows", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "success", "event": "push", "created_at": "2026-11-06T05:11:52Z"},
  {"id": 42167031250, "name": "golangci-lint", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "success", "event": "push", "created_at": "2026-11-06T05:11:52Z"},
  {"id": 42167031229, "name": "Build and Test", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "success", "event": "push", "created_at": "2026-11-06T05:11:52Z"},
  {"id": 42167031683, "name": "Release", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "failure", "event": "push", "created_at": "2026-11-06T05:11:53Z"},
  {"id": 42167031213, "name": "govulncheck", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "success", "event": "push", "created_at": "2026-11-06T05:11:52Z"},
  {"id": 42167031202, "name": "Lint Markdown", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "success", "event": "push", "created_at": "2026-11-06T05:11:52Z"},
  {"id": 42167031195, "name": "CodeQL", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "success", "event": "push", "created_at": "2026-11-06T05:11:52Z"}
]
EOF
}

derive() { # derive <jq filter> -> runs JSON
  recorded_all_success | jq -c "${1}"
}

expect() { # expect <scenario> <runs-json> <want>
  local scenario="$1" input="$2" want="$3" got
  got=$(decide <<<"${input}")
  if [ "${got}" = "${want}" ]; then
    echo "ok   ${scenario}"
  else
    echo "FAIL ${scenario}"
    echo "  want: ${want}"
    echo "  got:  ${got}"
    exit 1
  fi
}

# --- gating scenarios --------------------------------------------------------

# The last required workflow to finish sees every required workflow
# successful (recorded data; unrelated Auto Tag/Release runs are ignored).
expect "all required succeeded -> tag" \
  "$(recorded_all_success)" \
  "tag|all required workflows succeeded"

# A completion that arrives while another required workflow is still running
# is a clean skip naming what is pending.
expect "golangci-lint still in progress -> clean skip" \
  "$(derive 'map(if .name == "golangci-lint" then .status = "in_progress" | .conclusion = null else . end)')" \
  "skip|golangci-lint"

# Queued counts as not completed, too.
expect "govulncheck queued -> clean skip" \
  "$(derive 'map(if .name == "govulncheck" then .status = "queued" | .conclusion = null else . end)')" \
  "skip|govulncheck"

# A required workflow that has not produced any run yet (transient for the
# five always-on workflows) also skips cleanly.
expect "Lint Markdown absent -> clean skip" \
  "$(derive 'map(select(.name != "Lint Markdown"))')" \
  "skip|Lint Markdown"

# Several pending workflows are all named, in required-list order.
expect "two pending -> skip names both" \
  "$(derive 'map(if .name == "golangci-lint" then .status = "in_progress" | .conclusion = null elif .name == "govulncheck" then .status = "queued" | .conclusion = null else . end)')" \
  "skip|golangci-lint, govulncheck"

# Once everything completed, a failed required workflow blocks the tag.
expect "govulncheck failed -> no tag" \
  "$(derive 'map(if .name == "govulncheck" then .conclusion = "failure" else . end)')" \
  "no-tag|govulncheck"

# A capacity-cancelled required run (see the macOS re-run workflow) is not a
# success and must not release.
expect "Build and Test cancelled -> no tag" \
  "$(derive 'map(if .name == "Build and Test" then .conclusion = "cancelled" else . end)')" \
  "no-tag|Build and Test"

# Optional gates: CodeQL blocks only when it completed without success. An
# absent or still-running optional workflow never blocks, because its
# completion does not trigger Auto Tag.
expect "CodeQL failed -> no tag" \
  "$(derive 'map(if .name == "CodeQL" then .conclusion = "failure" else . end)')" \
  "no-tag|CodeQL"
expect "CodeQL still running -> tag" \
  "$(derive 'map(if .name == "CodeQL" then .status = "in_progress" | .conclusion = null else . end)')" \
  "tag|all required workflows succeeded"
expect "CodeQL absent -> tag" \
  "$(derive 'map(select(.name != "CodeQL"))')" \
  "tag|all required workflows succeeded"

# Re-runs: the most recent run of a workflow supersedes earlier ones (ids
# grow with time; jq keeps the highest id per name).
expect "golangci-lint re-run in progress supersedes its success -> skip" \
  "$(derive '. + [{"id": 42167031251, "name": "golangci-lint", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "in_progress", "conclusion": null, "event": "workflow_run", "created_at": "2026-11-06T05:12:01Z"}]')" \
  "skip|golangci-lint"
expect "golangci-lint re-run success supersedes an earlier failure -> tag" \
  "$(derive 'map(if .name == "golangci-lint" then .conclusion = "failure" else . end) | . + [{"id": 42167031252, "name": "golangci-lint", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "success", "event": "workflow_run", "created_at": "2026-11-06T05:12:02Z"}]')" \
  "tag|all required workflows succeeded"
expect "an older failure after a newer success does not regress the state -> tag" \
  "$(derive '. + [{"id": 42167031190, "name": "golangci-lint", "head_branch": "master", "head_sha": "52034ab2f35bd04a7b91f1a044284a234399c688", "status": "completed", "conclusion": "failure", "event": "workflow_run", "created_at": "2026-11-06T05:11:00Z"}]')" \
  "tag|all required workflows succeeded"

# Duplicate completion: two Auto Tag instances for the same commit each see
# the same all-success state and both would proceed to tag. Exactly one tag
# is guaranteed by the workflow-level concurrency group plus the tip check
# and atomic push in the release steps (asserted statically below); that
# part can only be proven end-to-end after merge.
d1=$(decide <<<"$(recorded_all_success)")
d2=$(decide <<<"$(recorded_all_success)")
if [ "${d1}" = "tag|all required workflows succeeded" ] &&
   [ "${d2}" = "tag|all required workflows succeeded" ]; then
  echo "ok   duplicate completion: both gate runs proceed (dedup enforced by concurrency + tip check)"
else
  echo "FAIL duplicate completion: got ${d1} / ${d2}"
  exit 1
fi

# --- static guarantees -------------------------------------------------------

# Trigger list matches required_workflows exactly (the two copies must not
# drift: the trigger decides which completions re-run the gate; the array
# decides what the gate waits for).
in_trigger=$(sed -n '/^    workflows:/,/^    types:/p' "${workflow}" |
  sed -e '/^    workflows:/d' -e '/^    types:/d' \
      -e 's/^[[:space:]]*-[[:space:]]*//' -e 's/"//g' -e '/^[[:space:]]*$/d')
# The array was eval'd from the workflow's gating block, so shellcheck cannot
# see the assignment.
# shellcheck disable=SC2154
expected_list=$(printf '%s\n' "${required_workflows[@]}")
if [ "${expected_list}" = "${in_trigger}" ]; then
  echo "ok   workflow_run trigger list matches required_workflows"
else
  echo "FAIL workflow_run trigger list differs from required_workflows:"
  echo "  expected: ${expected_list//$'\n'/, }"
  echo "  trigger:  ${in_trigger//$'\n'/, }"
  exit 1
fi

# The fixed wait is gone: no polling loop left in the Verify step.
if grep -q 'sleep 15' "${workflow}" || grep -q 'retrying' "${workflow}"; then
  echo "FAIL fixed wait still present in Verify step"
  exit 1
fi
echo "ok   no fixed wait/polling loop remains"

# Serialisation: a per-commit concurrency group that never cancels the
# running instance (a cancelled mid-release run could strand a release).
# shellcheck disable=SC2016  # the patterns quote ${{ }} literally on purpose
if grep -q '^concurrency:' "${workflow}" &&
   grep -q 'group: auto-tag-\${{ github.event.workflow_run.head_sha }}' "${workflow}" &&
   grep -q '^  cancel-in-progress: false' "${workflow}"; then
  echo "ok   concurrency group keyed on head SHA, cancel-in-progress false"
else
  echo "FAIL concurrency group missing or wrong"
  exit 1
fi

# Superseded commits are still guarded by the tip check and the atomic push.
if grep -q 'no longer the tip of master' "${workflow}" &&
   grep -q -- 'push --atomic origin HEAD:master' "${workflow}"; then
  echo "ok   tip check and atomic push guard remain"
else
  echo "FAIL tip check or atomic push missing"
  exit 1
fi

# No event-field interpolation inside run: blocks (a run block is a `run: |`
# line and every following line indented deeper than it).
# shellcheck disable=SC2016  # the pattern quotes ${{ }} literally on purpose
if awk '
  { indent = match($0, /[^ ]/) - 1 }
  /^ *run: \|/ { runindent = indent; inrun = 1; next }
  inrun && NF == 0 { next }
  inrun && indent > runindent { print; next }
  inrun { inrun = 0 }
' "${workflow}" | grep -q '\${{'; then
  echo "FAIL event field interpolated inside a run: block"
  exit 1
fi
echo "ok   no event fields interpolated inside run: blocks"

echo "all gate tests passed"
