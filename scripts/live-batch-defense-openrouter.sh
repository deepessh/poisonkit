#!/bin/bash
# poisonkit v0.3 live DEFENSE verification batch — OpenRouter (paid tier).
# NOTE: experiment-harness script, not part of the toolkit itself. Hardcodes
# the local repo path; adapt before reusing.
#
# Usage: live-batch-defense-openrouter.sh <model> <prefix>
#   e.g. live-batch-defense-openrouter.sh poolside/laguna-xs-2.1 or-laguna-def
#
# Sequential with short sleeps (20-30s, paid API so lighter pacing than the
# free tier); or-chat already retries transient 429/5xx internally with
# backoff, so a single poisonkit call may take a while — the `timeout`
# wrapper (1500s) kills only true hangs. Resumable: skips valid completed
# JSONs. A failed-after-retries run leaves its .json EMPTY so a later resume
# retries it; a .json containing valid JSON (even INCONCL) counts as done.
cd ~/workspace/agent-security-toolkit
source .venv/bin/activate
export POISONKIT_MODEL="${1:?usage: $0 <model> <prefix>}"
PREFIX="${2:?usage: $0 <model> <prefix>}"
# POISONKIT_OR_CLI defaults to ~/workspace/skills/openrouter/bin/or-chat.
R=results

run_one() {  # $1=outfile-prefix $2=poisonkit-args...
  local prefix="$1"; shift
  local json="$R/${prefix}.json" err="$R/${prefix}.stderr"
  if [ -s "$json" ] && python3 -c "import json,sys;json.load(open('$json'))" 2>/dev/null; then
    echo "skip (done): $prefix"
    return 0
  fi
  timeout 1500 poisonkit "$@" --provider openrouter --json > "$json" 2> "$err"
  local code=$?
  if grep -qEi "429|rate.?limit|too many requests" "$err"; then
    echo "RATE_LIMITED at $prefix — will back off"
    return 9
  fi
  if ! python3 -c "import json;json.load(open('$json'))" 2>/dev/null; then
    echo "CRASH(empty json): $prefix (exit $code)"
    : > "$json"  # keep empty so resume retries it
    return 1
  fi
  echo "ok: $prefix (exit $code)"
  return 0
}

limited=0
run_retried() {  # $1=prefix then poisonkit args; up to 3 attempts
  local prefix="$1"; shift
  for attempt in 1 2 3; do
    run_one "$prefix" "$@"
    local rc=$?
    if [ $rc -eq 9 ]; then
      # rate-limited: back off 2-5 min, then try once more per attempt
      local backoff=$((120 + RANDOM % 180))
      echo "429 backoff ${backoff}s before retry (round $attempt/3)"
      sleep "$backoff"
      run_one "$prefix" "$@"
      rc=$?
      [ $rc -eq 9 ] && { echo "RATE_LIMIT persists at $prefix after backoff"; return 9; }
    fi
    if [ -s "$R/${prefix}.json" ] && \
       python3 -c "import json;json.load(open('$R/${prefix}.json'))" 2>/dev/null; then
      return 0
    fi
    echo "retry $attempt/3 for $prefix after 60s"
    sleep 60
  done
  echo "GAVE UP: $prefix after 3 attempts"
  return 1
}

for pair in "rug-pull:desc-pin" "rag-poison:output-scan" "confirm-bypass:confirm-all" "param-poison:schema-scan"; do
  atk="${pair%%:*}"; def="${pair##*:}"
  for i in 1 2 3; do
    run_retried "${PREFIX}-${def}-vs-${atk}-${i}" run --attack "$atk" --defense "$def" \
      || { [ $? -eq 9 ] && limited=1 && break 2; }
    sleep 25
  done
done
for def in desc-pin output-scan confirm-all schema-scan; do
  for i in 1 2; do
    run_retried "${PREFIX}-benign-${def}-${i}" benign --defense "$def" \
      || { [ $? -eq 9 ] && limited=1 && break 2; }
    sleep 25
  done
done
for i in 1 2; do
  run_retried "${PREFIX}-benign-none-${i}" benign \
    || { [ $? -eq 9 ] && limited=1 && break 2; }
  sleep 25
done
echo "batch done limited=$limited"
ls "$R"/${PREFIX}-*.json 2>/dev/null | wc -l
