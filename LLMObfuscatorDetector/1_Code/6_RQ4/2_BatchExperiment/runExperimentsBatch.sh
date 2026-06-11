#!/usr/bin/env bash
set -u

### Configuration ###
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RQ4_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INPUT_CSV="$RQ4_DIR/Data/sampledApps.csv"
OUTPUT_ROOT="$RQ4_DIR/Results/"
PYTHON_BIN="${PYTHON_BIN:-python3}"
EXPERIMENT_SCRIPT="$SCRIPT_DIR/experimentsBatch.py"
LOGS_BATCH="$OUTPUT_ROOT/logsBatchSummary.out"
LOGS_FULL="$OUTPUT_ROOT/logsBatchFull.out"
POLL_INTERVAL="${POLL_INTERVAL:-60}"

### MODELS ###
MODELS=(
  "gpt-4o-mini"
  # "gpt-5-mini"
)

### PROMPTS ###
PROMPTS=(
  # "ObfuscationDetectionV1"
  # "ObfuscationDetectionV2"
  "ObfuscationDetectionV3"
)

logBatch() {
  printf '%s\n' "$1" | tee -a "$LOGS_BATCH"
}

printErrorAndExit() {
  logBatch ''
  logBatch "--- ❌ $1"
  exit 1
}

: > "$LOGS_BATCH"
: > "$LOGS_FULL"

[ -f "$INPUT_CSV" ] || printErrorAndExit "Input CSV not found: $INPUT_CSV"
[ -f "$EXPERIMENT_SCRIPT" ] || printErrorAndExit "Experiment script not found: $EXPERIMENT_SCRIPT"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || printErrorAndExit "Python binary not found in PATH: $PYTHON_BIN"

TOTAL_RUNS=$(( ${#PROMPTS[@]} * ${#MODELS[@]} ))

batchStartEpoch="$(date +%s)"
batchStartTime="$(date '+%Y-%m-%d %H:%M:%S')"

logBatch '============================================================'
logBatch '--- 🚀 OPENAI SHARED BATCH CONFIGURATION'
logBatch "--- 📂 Input CSV         : $INPUT_CSV"
logBatch "--- 💾 Output Root       : $OUTPUT_ROOT"
logBatch "--- 🐍 Python Bin        : $PYTHON_BIN"
logBatch "--- ⏱️ Poll Every        : ${POLL_INTERVAL}s"
logBatch "--- 📝 Prompts Selected  : ${#PROMPTS[@]}"
logBatch "--- 🤖 Models Selected   : ${#MODELS[@]}"
logBatch "--- 🔢 Logical Runs      : $TOTAL_RUNS"
logBatch "--- 📝 logsBatch         : $LOGS_BATCH"
logBatch "--- 📝 logsFull          : $LOGS_FULL"
logBatch '============================================================'
logBatch ''
logBatch '+++ ⭐ STARTING OPENAI SHARED BATCH EXECUTION ⭐ +++'
logBatch "--> 🕒 START TIME: $batchStartTime"
logBatch "--- 📦 All logical runs will be queued into shared OpenAI Batch submission(s)."

runStartEpoch="$(date +%s)"
summaryPattern='^(--- ▶️ Run|--- 📝 Prompt|--- 🤖 Model|--- 🔄 Existing Results|--- 🧾 Total Shared Batch Requests|--- 🔁 Shared Batch Attempt|--- 📦 Attempt|--- 🆔 Batch ID|--- ⏳ Batch status|--- 🏁 Batch terminal status|--- ✅ Valid Replies|--- 🔁 Pending Retries|--- 💾 Reports saved|--- 🔚 END)'

campaignExitCode=0
if "$PYTHON_BIN" -u "$EXPERIMENT_SCRIPT" \
  --input-csv "$INPUT_CSV" \
  --models "${MODELS[@]}" \
  --prompt-ids "${PROMPTS[@]}" \
  --poll-interval "$POLL_INTERVAL" \
  --output-folder "$OUTPUT_ROOT" \
  > >(tee -a "$LOGS_FULL" | awk -v pattern="$summaryPattern" '$0 ~ pattern { print; fflush(); }' >> "$LOGS_BATCH") 2>&1
then
  runEndEpoch="$(date +%s)"
  runElapsedSeconds=$((runEndEpoch - runStartEpoch))
  runElapsedHours=$((runElapsedSeconds / 3600))
  runElapsedMinutes=$(((runElapsedSeconds % 3600) / 60))
  runElapsedRemainderSeconds=$((runElapsedSeconds % 60))
  logBatch "--- ✅ Completed shared Batch campaign | elapsed=${runElapsedHours}h ${runElapsedMinutes}m ${runElapsedRemainderSeconds}s (${runElapsedSeconds}s)"
else
  exitCode=$?
  runEndEpoch="$(date +%s)"
  runElapsedSeconds=$((runEndEpoch - runStartEpoch))
  runElapsedHours=$((runElapsedSeconds / 3600))
  runElapsedMinutes=$(((runElapsedSeconds % 3600) / 60))
  runElapsedRemainderSeconds=$((runElapsedSeconds % 60))
  logBatch "--- ❌ Failed shared Batch campaign | elapsed=${runElapsedHours}h ${runElapsedMinutes}m ${runElapsedRemainderSeconds}s (${runElapsedSeconds}s) | exitCode=$exitCode"
  campaignExitCode=$exitCode
fi

batchEndEpoch="$(date +%s)"
batchEndTime="$(date '+%Y-%m-%d %H:%M:%S')"
elapsedSeconds=$((batchEndEpoch - batchStartEpoch))
elapsedHours=$((elapsedSeconds / 3600))
elapsedMinutes=$(((elapsedSeconds % 3600) / 60))
elapsedRemainderSeconds=$((elapsedSeconds % 60))

logBatch ''
logBatch '++++++++++++++++++++++++++++++++++++++++++++++++++++'
logBatch '+++ ⭐ FINISHED OPENAI SHARED BATCH EXECUTION ⭐ +++'
logBatch "--> 🕒 Batch End Time   : $batchEndTime "
logBatch "--> ⏱️ Elapsed Time     : ${elapsedHours}h ${elapsedMinutes}m ${elapsedRemainderSeconds}s (${elapsedSeconds}s)"

exit "$campaignExitCode"
