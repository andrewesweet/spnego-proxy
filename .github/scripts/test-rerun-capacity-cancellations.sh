#!/usr/bin/env bash
# Tests the capacity-cancellation predicate embedded in
# .github/workflows/rerun-capacity-cancellations.yml.
#
# That workflow checks out nothing by design, so the predicate cannot live
# in a repository script the workflow would read at run time. Instead the
# predicate is embedded in the workflow YAML between the JQ_CAPACITY_PREDICATE
# heredoc markers. This test extracts those exact lines and evaluates them
# against recorded Actions API responses
# (GET /repos/{owner}/{repo}/actions/runs/<id>/attempts/<n>/jobs) from
# andrewesweet/spnego-proxy, plus two composites assembled from the same
# recorded responses.
#
# Usage: .github/scripts/test-rerun-capacity-cancellations.sh
# Requires: jq, sed
set -euo pipefail

script_dir="$(dirname "$0")"
workflow="$script_dir/../workflows/rerun-capacity-cancellations.yml"
testdata="$script_dir/testdata/rerun-capacity-cancellations"

predicate_file="$(mktemp)"
composite_a="$(mktemp)"
composite_b="$(mktemp)"
step_file="$(mktemp)"
step_temp="$(mktemp -d)"
trap 'rm -f "$predicate_file" "$composite_a" "$composite_b" "$step_file"; rm -rf "$step_temp"' EXIT

# Extract the predicate verbatim from the workflow's run block (the block
# scalar indents every line uniformly, so stripping leading whitespace on
# each line reproduces the executed script).
sed -n "/<<'JQ_CAPACITY_PREDICATE'/,/^[[:space:]]*JQ_CAPACITY_PREDICATE[[:space:]]*\$/p" \
  "$workflow" | sed '1d;$d; s/^[[:space:]]*//' > "$predicate_file"

if [ ! -s "$predicate_file" ]; then
  echo "FAIL: predicate not extracted from $workflow" >&2
  exit 1
fi

# Composite 1: a capacity-cancelled job alongside a genuinely failed job.
# Re-run-failed-jobs would repeat the real failure, so this must be false.
jq --slurpfile gf "$testdata/genuine-failure.json" \
  '.jobs += [($gf[0].jobs[] | select(.conclusion == "failure"))]' \
  "$testdata/cap-bt-attempt5.json" > "$composite_a"

# Composite 2: the cancelled job acquired a runner and ran a step (a
# mid-run cancellation or a timeout), so the shape is not capacity.
jq '.jobs[0].runner_name = "GitHub Actions 1000000000"
    | .jobs[0].steps = [{"name": "Set up job", "conclusion": "success", "number": 1, "started_at": "2026-11-05T16:20:00Z", "completed_at": "2026-11-05T16:20:10Z"}]' \
  "$testdata/cap-bt-attempt5.json" > "$composite_b"

# Evaluate the predicate exactly as production does. The workflow reads it
# with "gh api --paginate --slurp", which wraps the response pages in a JSON
# array; "jq '[.]'" wraps a recorded single-page fixture the same way.
evaluate() {
  jq '[.]' "$1" | jq -e --arg capacity_conclusion "$2" -f "$predicate_file" > /dev/null
}

pass=0
fail=0

check() {
  local label="$1" file="$2" conclusion="$3" expected="$4" got
  if evaluate "$file" "$conclusion"; then
    got=true
  else
    got=false
  fi
  if [ "$got" = "$expected" ]; then
    pass=$((pass + 1))
    echo "ok   $label -> $got"
  else
    fail=$((fail + 1))
    echo "FAIL $label -> $got, want $expected" >&2
  fi
}

check "capacity: golangci-lint attempt 8 (recorded)" \
  "$testdata/cap-lint-attempt8.json" failure true
check "capacity: build-and-test attempt 5 (recorded)" \
  "$testdata/cap-bt-attempt5.json" failure true
check "capacity: both macOS legs cancelled (recorded)" \
  "$testdata/cap-bt-both-macos.json" failure true
check "capacity: codeql with skipped jobs (recorded)" \
  "$testdata/cap-codeql-skipped.json" failure true
check "genuine failure: lint jobs failed (recorded)" \
  "$testdata/genuine-failure.json" failure false
check "manual cancel: run-level cancel with queued job (recorded)" \
  "$testdata/manual-cancel-queued.json" cancelled false
check "release cancel: run-level cancel (recorded)" \
  "$testdata/release-run-cancelled.json" cancelled false
check "composite: capacity cancel plus genuine failure" \
  "$composite_a" failure false
check "composite: cancelled job that acquired a runner and ran" \
  "$composite_b" failure false
check "policy: run-level cancellation with capacity-shaped macOS job" \
  "$testdata/cap-bt-attempt5.json" cancelled false

jq '(.jobs[] | select(.conclusion == "cancelled") | .labels) = ["ubuntu-latest"]' \
  "$testdata/cap-bt-attempt5.json" > "$step_temp/linux.json"
jq '(.jobs[] | select(.conclusion == "cancelled")) |=
  if .name == "build-macos (arm64)" then .labels = ["ubuntu-latest"] else . end' \
  "$testdata/cap-bt-both-macos.json" > "$step_temp/mixed.json"
jq '(.jobs[] | select(.conclusion == "cancelled") | .conclusion) = "timed_out"' \
  "$testdata/cap-bt-attempt5.json" > "$step_temp/timeout.json"
check "policy: Linux cancellation alongside successful macOS jobs" "$step_temp/linux.json" failure false
check "policy: mixed macOS and Linux cancellations" "$step_temp/mixed.json" failure false
check "policy: macOS timeout" "$step_temp/timeout.json" failure false

for labels in '["macos-15"]' '["macos-26-intel"]' '["macos-latest-large"]' '["macos-15-xlarge"]'; do
  jq --argjson labels "$labels" '(.jobs[] | select(.conclusion == "cancelled") | .labels) = $labels' \
    "$testdata/cap-bt-attempt5.json" > "$step_temp/labels.json"
  check "policy: hosted macOS $labels" "$step_temp/labels.json" failure true
done
for labels in '["windows-latest"]' '["self-hosted","macos-latest"]' '["self-hosted","macOS"]' '["macos-custom"]' '[]' 'null'; do
  jq --argjson labels "$labels" '(.jobs[] | select(.conclusion == "cancelled") | .labels) = $labels' \
    "$testdata/cap-bt-attempt5.json" > "$step_temp/labels.json"
  check "policy: unsupported runner labels $labels" "$step_temp/labels.json" failure false
done

sed -n '/^        run: |$/,$p' "$workflow" | sed '1d; s/^          //' > "$step_file"

gh() {
  case "$*" in
    "api --paginate --slurp /repos/test/repo/actions/runs/123/attempts/$RUN_ATTEMPT/jobs?per_page=100")
      echo jobs >> "$TEST_API_LOG"
      jq '[.]' "$TEST_JOBS_FILE"
      ;;
    "api /repos/test/repo/actions/runs/123")
      echo run >> "$TEST_API_LOG"
      if [ "$TEST_RUN_METADATA" = error ]; then return 1; fi
      printf '%s\n' "$TEST_RUN_METADATA"
      ;;
    "api --method POST /repos/test/repo/actions/runs/123/rerun-failed-jobs")
      echo post >> "$TEST_API_LOG"
      ;;
    *) return 1 ;;
  esac
}
export -f gh

check_step() {
  local label="$1" attempt="$2" metadata="$3" expected_calls="$4" expected_status="${5:-0}" status=0
  local jobs="${6:-$testdata/cap-bt-attempt5.json}"
  : > "$step_temp/api.log"
  RUNNER_TEMP="$step_temp" GITHUB_REPOSITORY=test/repo RUN_ID=123 \
    RUN_ATTEMPT="$attempt" RUN_CONCLUSION=failure \
    TEST_API_LOG="$step_temp/api.log" TEST_RUN_METADATA="$metadata" \
    TEST_JOBS_FILE="$jobs" \
    bash -e -o pipefail "$step_file" > "$step_temp/output" 2>&1 || status=$?
  if [ "$status" -eq "$expected_status" ] && [ "$(cat "$step_temp/api.log")" = "$expected_calls" ]; then
    pass=$((pass + 1))
    echo "ok   $label"
  else
    fail=$((fail + 1))
    echo "FAIL $label: status $status; calls $(cat "$step_temp/api.log")" >&2
    cat "$step_temp/output" >&2
  fi
}

check_step "current completed attempt is re-run" 5 \
  '{"run_attempt":5,"status":"completed","conclusion":"failure"}' $'jobs\nrun\npost'
check_step "superseded attempt cannot re-run a later failure" 5 \
  '{"run_attempt":6,"status":"completed","conclusion":"failure"}' $'jobs\nrun'
check_step "stale attempt cannot bypass cap" 11 \
  '{"run_attempt":12,"status":"completed","conclusion":"failure"}' $'jobs\nrun'
check_step "superseded attempt cannot re-run an active run" 5 \
  '{"run_attempt":6,"status":"in_progress","conclusion":null}' $'jobs\nrun'
check_step "current attempt must still be completed" 5 \
  '{"run_attempt":5,"status":"queued","conclusion":null}' $'jobs\nrun'
check_step "current conclusion must match evaluated conclusion" 5 \
  '{"run_attempt":5,"status":"completed","conclusion":"success"}' $'jobs\nrun'
check_step "metadata lookup failure prevents POST" 5 error $'jobs\nrun' 1
check_step "policy: genuine failure plus capacity cancellation prevents POST" 5 \
  '{"run_attempt":5,"status":"completed","conclusion":"failure"}' jobs 0 "$composite_a"
check_step "policy: Linux cancellation prevents POST" 5 \
  '{"run_attempt":5,"status":"completed","conclusion":"failure"}' jobs 0 "$step_temp/linux.json"
check_step "policy: mixed macOS and Linux cancellations prevent POST" 5 \
  '{"run_attempt":5,"status":"completed","conclusion":"failure"}' jobs 0 "$step_temp/mixed.json"
check_step "policy: timeout prevents POST" 5 \
  '{"run_attempt":5,"status":"completed","conclusion":"failure"}' jobs 0 "$step_temp/timeout.json"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
