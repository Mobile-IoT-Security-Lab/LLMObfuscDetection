#!/usr/bin/env bash
set -u

### Configuration ###
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# INPUT_ROOT="$PROJECT_ROOT/0_Data/InputApksTest/"
INPUT_ROOT="$PROJECT_ROOT/0_Data/InputApks/"
OUTPUT_ROOT="$PROJECT_ROOT/0_Data/Results/"
PYTHON_BIN="${PYTHON_BIN:-python3}"
EXPERIMENT_SCRIPT="$SCRIPT_DIR/experiments.py"
LOGS_BATCH="$SCRIPT_DIR/logsSummary.out"
LOGS_FULL="$SCRIPT_DIR/logsFull.out"
POLL_INTERVAL="${POLL_INTERVAL:-60}"

### MODELS ###
MODELS=(
  # "gpt-4o-mini"
  "gpt-5-mini"
)

### PROMPTS ###
PROMPTS=(
  "ObfuscationClassificationV1"
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

[ -d "$INPUT_ROOT" ] || printErrorAndExit "Input root not found: $INPUT_ROOT"
[ -f "$EXPERIMENT_SCRIPT" ] || printErrorAndExit "Experiment script not found: $EXPERIMENT_SCRIPT"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || printErrorAndExit "Python binary not found in PATH: $PYTHON_BIN"

mapfile -t TECHNIQUE_DIRS < <(find "$INPUT_ROOT" -mindepth 1 -maxdepth 1 -type d ! -name "Clean" | sort)
[ "${#TECHNIQUE_DIRS[@]}" -gt 0 ] || printErrorAndExit "No obfuscation technique folders found inside $INPUT_ROOT"

TOTAL_RUNS=$(( ${#TECHNIQUE_DIRS[@]} * ${#PROMPTS[@]} * ${#MODELS[@]} ))

batchStartEpoch="$(date +%s)"
batchStartTime="$(date '+%Y-%m-%d %H:%M:%S')"

logBatch '============================================================'
logBatch '--- 🚀 OPENAI SHARED BATCH CONFIGURATION'
logBatch "--- 📂 Input Root        : $INPUT_ROOT"
logBatch "--- 💾 Output Root       : $OUTPUT_ROOT"
logBatch "--- 🐍 Python Bin        : $PYTHON_BIN"
logBatch "--- ⏱️ Poll Every        : ${POLL_INTERVAL}s"
logBatch "--- 🧪 Techniques Found  : ${#TECHNIQUE_DIRS[@]}"
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
summaryPattern='^(--- ▶️ Run|--- 📝 Prompt|--- 🤖 Model|--- 📁 Technique|--- 🔄 Existing Results|--- 🧾 Total Shared Batch Requests|--- 🔁 Shared Batch Attempt|--- 📦 Attempt|--- 🆔 Batch ID|--- ⏳ Batch status|--- 🏁 Batch terminal status|--- ✅ Valid Replies|--- 🔁 Pending Retries|--- 💾 Reports saved|--- 🔚 END)'

if "$PYTHON_BIN" -u "$EXPERIMENT_SCRIPT" \
  --input-root "$INPUT_ROOT" \
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
