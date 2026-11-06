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
# Dependencies: bash, jq, ruby (with YAML). Run in CI by the gate tests job
# in lint-workflows.yml; run it locally when touching the Auto Tag workflow.

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
# sourced as-is. decide() and the loop assign decision at eval time, which
# the linter cannot see; the inputs below are read by the extracted blocks.
# shellcheck disable=SC2154
# shellcheck disable=SC2034
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

recorded_all_success | ruby "${script_dir}/test-auto-tag-workflow.rb" "${workflow}"

# --- retry behaviour (the shipped gating loop) ------------------------------

# The gating-loop block executes when evaluated, so its gh and sleep calls
# are stubbed first: API responses are served from a queue (the last one
# repeats), and re-query delays are counted instead of waited.
loop_block="$(awk '
  /^ *# --- gating loop/ {on = 1; next}
  /^ *# --- end gating loop/ {on = 0}
  on {print}
' "${workflow}")"
[ -n "${loop_block}" ] || { echo "FAIL: gating loop block did not extract"; exit 1; }

gh_log="$(mktemp)"
trap 'rm -f "${gh_log}"' EXIT
gh_responses=()
gh() { # serve queued API responses; the last one repeats. Call counts land
       # in a file because fetch_runs runs inside a command substitution.
  local idx
  idx=$(wc -l < "${gh_log}")
  if [ "${idx}" -ge "${#gh_responses[@]}" ]; then
    idx=$((${#gh_responses[@]} - 1))
  fi
  printf '%s\n' "${gh_responses[${idx}]}"
  echo served >> "${gh_log}"
}
sleep() { # record the re-query delay instead of waiting
  sleep_calls=$((sleep_calls + 1))
  if [ "${1}" != "30" ]; then
    echo "FAIL: re-query delay is ${1}s, want 30s"
    exit 1
  fi
}
# shellcheck disable=SC2034  # consumed by the extracted gating-loop block
REPOSITORY=andrewesweet/spnego-proxy
# shellcheck disable=SC2034  # consumed by the extracted gating-loop block
SHA=52034ab2f35bd04a7b91f1a044284a234399c688
pending_runs="$(derive 'map(if .name == "golangci-lint" then .status = "in_progress" | .conclusion = null else . end)')"

# fetch_runs consumes the array of page documents that gh api --slurp
# emits ([{"workflow_runs": [...]}, ...], the shape the .rb harness stubs
# too), not the flat run arrays decide() reads.
page() {
  jq -cn --argjson runs "$1" '[{workflow_runs: $runs}]'
}

expect_loop() { # expect_loop <scenario> <want-decision> <want-gh-calls> <want-sleep-calls>
  # gh_responses is queued by the caller; only the counters reset here.
  local scenario="$1" want_decision="$2" want_gh="$3" want_sleep="$4" gh_served
  : > "${gh_log}"
  sleep_calls=0
  eval "${loop_block}"
  gh_served=$(wc -l < "${gh_log}")
  # decision is assigned by the eval'd gating-loop block
  # shellcheck disable=SC2154
  if [ "${decision}" = "${want_decision}" ] && [ "${gh_served}" = "${want_gh}" ] &&
    [ "${sleep_calls}" = "${want_sleep}" ]; then
    echo "ok   ${scenario}"
  else
    echo "FAIL ${scenario}"
    echo "  decision:    want ${want_decision}, got ${decision}"
    echo "  gh calls:    want ${want_gh}, got ${gh_served}"
    echo "  sleep calls: want ${want_sleep}, got ${sleep_calls}"
    exit 1
  fi
}

# Completion-event lag: the run that just finished is missing from the first
# response and appears on re-query, so the final completion releases.
gh_responses=()
gh_responses+=("$(page "${pending_runs}")")
gh_responses+=("$(page "$(recorded_all_success)")")
expect_loop "API lag on final completion -> re-query then tag" \
  "tag|all required workflows succeeded" 2 1

# A genuinely running workflow still skips cleanly after the bounded wait;
# its completion re-fires the gate later.
gh_responses=()
gh_responses+=("$(page "${pending_runs}")")
expect_loop "persistent pending -> clean skip after bounded re-queries" \
  "skip|golangci-lint" 3 2

# No lag: a single fetch decides without any re-query.
gh_responses=()
gh_responses+=("$(page "$(recorded_all_success)")")
expect_loop "no lag -> single fetch, no re-query" \
  "tag|all required workflows succeeded" 1 0

echo "all gate tests passed"
