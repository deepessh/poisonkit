#!/bin/bash
# poisonkit v0.3 live DEFENSE verification batch — NVIDIA NIM free tier.
# Verbose-logging driver. Resumable: skips valid completed JSONs.
# Usage: live-batch-defense-v03b.sh <model> <prefix> <logfile>
cd ~/workspace/agent-security-toolkit || exit 1
source .venv/bin/activate || exit 1
MODEL="${1:?usage: $0 <model> <prefix> <logfile>}"
PREFIX="${2:?usage: $0 <model> <prefix> <logfile>}"
LOG="${3:?usage: $0 <model> <prefix> <logfile>}"
export POISONKIT_MODEL="$MODEL"
export POISONKIT_NIM_CLI="$PWD/scripts/nim-chat-60s"
R=results

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

run_one() {  # $1=prefix $2..=poisonkit args
  local prefix="$1"; shift
  local json="$R/${prefix}.json" err="$R/${prefix}.stderr"
  if [ -s "$json" ] && python3 -c "import json,sys;json.load(open('$json'))" 2>/dev/null; then
    log "skip (done): $prefix"
    return 2
  fi
  log "START: $prefix ($*)"
  timeout 2400 poisonkit "$@" --provider nvidia --json > "$json" 2> "$err"
  local code=$?
  log "END: $prefix (exit $code)"
  if grep -qEi "429|rate.?limit|too many requests" "$err"; then
    log "RATE_LIMITED at $prefix — aborting batch"
    return 9
  fi
  if ! python3 -c "import json;json.load(open('$json'))" 2>/dev/null; then
    log "CRASH(empty json): $prefix (exit $code)"
    : > "$json"
    return 1
  fi
  return 0
}

run_retried() {
  local prefix="$1"; shift
  for attempt in 1 2 3; do
    run_one "$prefix" "$@"
    local rc=$?
    [ $rc -eq 9 ] && return 9
    [ $rc -eq 2 ] && return 2   # skipped: already done, no retry/sleep needed
    if [ -s "$R/${prefix}.json" ] && \
       python3 -c "import json;json.load(open('$R/${prefix}.json'))" 2>/dev/null; then
      return 0
    fi
    log "retry $attempt/3 for $prefix after 180s"
    sleep 180
  done
  log "GAVE UP: $prefix after 3 attempts"
  return 1
}

limited=0
log "batch start: model=$MODEL prefix=$PREFIX"
for pair in "rug-pull:desc-pin" "rag-poison:output-scan" "confirm-bypass:confirm-all" "param-poison:schema-scan"; do
  atk="${pair%%:*}"; def="${pair##*:}"
  for i in 1 2 3; do
    run_retried "${PREFIX}-${def}-vs-${atk}-${i}" run --attack "$atk" --defense "$def"
    rc=$?
    if [ $rc -eq 9 ]; then limited=1; break 2; fi
    if [ $rc -ne 2 ]; then log "pace sleep 120s"; sleep 120; fi
  done
done
for def in desc-pin output-scan confirm-all schema-scan; do
  for i in 1 2; do
    run_retried "${PREFIX}-benign-${def}-${i}" benign --defense "$def"
    rc=$?
    if [ $rc -eq 9 ]; then limited=1; break 2; fi
    if [ $rc -ne 2 ]; then log "pace sleep 120s"; sleep 120; fi
  done
done
for i in 1 2; do
  run_retried "${PREFIX}-benign-none-${i}" benign
  rc=$?
  if [ $rc -eq 9 ]; then limited=1; break 2; fi
  if [ $rc -ne 2 ]; then log "pace sleep 120s"; sleep 120; fi
done
log "batch done limited=$limited"
ls "$R"/${PREFIX}-*.json 2>/dev/null | wc -l
