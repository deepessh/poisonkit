#!/bin/bash
# poisonkit v0.2 live verification batch — gpt-oss-20b on NVIDIA NIM free tier.
# NOTE: experiment-harness script, not part of the toolkit itself. Hardcodes
# the local repo path and a local nim-chat variant; adapt before reusing.
# Sequential with sleeps; aborts on HTTP 429 in stderr; tolerates transient
# nim-chat failures (records, continues). Resumable: skips valid JSONs.
cd ~/workspace/agent-security-toolkit
source .venv/bin/activate
export POISONKIT_MODEL=openai/gpt-oss-20b
# Local nim-chat variant with a 60s read timeout: the NIM free tier sometimes
# accepts a request and then stalls; healthy calls finish in <30s, so failing
# fast makes the retry loop below cheap. Original skill untouched.
export POISONKIT_NIM_CLI="$PWD/scripts/nim-chat-60s"
R=results

run_one() {  # $1=outfile-prefix $2=poisonkit-args...
  local prefix="$1"; shift
  local json="$R/${prefix}.json" err="$R/${prefix}.stderr"
  if [ -s "$json" ] && python3 -c "import json,sys;json.load(open('$json'))" 2>/dev/null; then
    echo "skip (done): $prefix"
    return 0
  fi
  timeout 1500 poisonkit "$@" --provider nvidia --json > "$json" 2> "$err"
  local code=$?
  if grep -qEi "429|rate.?limit|too many requests" "$err"; then
    echo "RATE_LIMITED at $prefix — aborting batch"
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

run_retried() {  # $1=prefix then poisonkit args; up to 3 attempts
  local prefix="$1"; shift
  for attempt in 1 2 3; do
    run_one "$prefix" "$@"
    local rc=$?
    [ $rc -eq 9 ] && return 9
    if [ -s "$R/${prefix}.json" ] && \
       python3 -c "import json;json.load(open('$R/${prefix}.json'))" 2>/dev/null; then
      return 0
    fi
    echo "retry $attempt/3 for $prefix after 120s"
    sleep 120
  done
  echo "GAVE UP: $prefix after 3 attempts"
  return 1
}

limited=0
for atk in rug-pull param-poison; do
  for i in 1 2 3 4 5; do
    run_retried "v02-${atk}-${i}" run --attack "$atk" || { [ $? -eq 9 ] && limited=1 && break 2; }
    sleep 120
  done
done
for pair in "rug-pull:desc-pin" "rag-poison:output-scan" "confirm-bypass:confirm-all"; do
  atk="${pair%%:*}"; def="${pair##*:}"
  for i in 1 2 3; do
    run_retried "v02-def-${def}-vs-${atk}-${i}" run --attack "$atk" --defense "$def" \
      || { [ $? -eq 9 ] && limited=1 && break 2; }
    sleep 120
  done
done
for def in desc-pin output-scan confirm-all; do
  for i in 1 2 3; do
    run_retried "v02-benign-${def}-${i}" benign --defense "$def" \
      || { [ $? -eq 9 ] && limited=1 && break 2; }
    sleep 120
  done
done
for i in 1 2 3; do
  run_retried "v02-benign-none-${i}" benign \
    || { [ $? -eq 9 ] && limited=1 && break 2; }
  sleep 120
done
echo "batch done limited=$limited"
ls "$R"/v02-*.json 2>/dev/null | wc -l
