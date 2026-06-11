#!/usr/bin/env bash
set -u

### Configuration ###
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RQ4_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INPUT_CSV="$RQ4_DIR/Data/sampledApps.csv"
OUTPUT_ROOT="$RQ4_DIR/Results/"
PYTHON_BIN="${PYTHON_BIN:-python3}"
EXPERIMENT_SCRIPT="$SCRIPT_DIR/experiments.py"
LOGS_BATCH="$OUTPUT_ROOT/logsSummary.out"
LOGS_FULL="$OUTPUT_ROOT/logsFull.out"

### MODELS ###
MODELS=(
  # "gpt-4o-mini"
  # "gpt-5-mini"
  # "gemini-3-flash-preview"
  "gpt-oss:20b"
  # "deepseek-r1:32b"
  # "gemma3:27b"
  # "qwen3:30b"
  # "llama3.1:8b"
  # "phi3:14b"
)

### PROMPTS ###
PROMPTS=(
  # "ObfuscationDetectionV1"
  "ObfuscationDetectionV2"
  # "ObfuscationDetectionV3"
)

### Logging helpers ###
logBatch() {
  printf '%s\n' "$1" | tee -a "$LOGS_BATCH"
}

logEnvConfiguration() {
  logBatch '============================================================'
  logBatch '--- 🚀 ENV CONFIGURATION'
  logBatch "--- 📂 Input CSV    : $INPUT_CSV"
  logBatch "--- 💾 Output Root  : $OUTPUT_ROOT"
  logBatch "--- 🐍 Python Bin   : $PYTHON_BIN"
  logBatch "--- 📝 logsBatch    : $LOGS_BATCH"
  logBatch "--- 📝 logsFull     : $LOGS_FULL"
  logBatch '============================================================'
  logBatch ''
}

logExperimentConfiguration() {
  logBatch '============================================================'
  logBatch '--- 🚀 EXPERIMENTS CONFIGURATION'
  logBatch "--- 📝 Prompts Selected : ${#PROMPTS[@]}"
  logBatch "--- 🤖 Models Selected  : ${#MODELS[@]}"
  logBatch "--- 🔢 Total Runs       : $TOTAL_RUNS"
  logBatch '============================================================'
  logBatch ''
}

printErrorAndExit() {
  logBatch ''
  logBatch "--- ❌ $1"
  exit 1
}

# Clear previous logs
: > "$LOGS_BATCH"
: > "$LOGS_FULL"

# !!! Program starts here !!!
# Log environment configuration
logEnvConfiguration

[ -f "$INPUT_CSV" ] || printErrorAndExit "Input CSV not found: $INPUT_CSV"
[ -f "$EXPERIMENT_SCRIPT" ] || printErrorAndExit "Experiment script not found: $EXPERIMENT_SCRIPT"
command -v "$PYTHON_BIN" >/dev/null 2>&1 || printErrorAndExit "Python binary not found in PATH: $PYTHON_BIN"

# Calculate total runs for progress tracking
TOTAL_RUNS=$(( ${#PROMPTS[@]} * ${#MODELS[@]} ))
CURRENT_RUN=0

# Log experiment configuration summary
logExperimentConfiguration

# Start batch execution
batchStartEpoch="$(date +%s)"
batchStartTime="$(date '+%Y-%m-%d %H:%M:%S')"

logBatch '+++ ⭐STARTING BATCH EXECUTION ⭐ +++'
logBatch "--> 🕒 START TIME: $batchStartTime"

# Run experiments for each prompt/model pair
for promptID in "${PROMPTS[@]}"; do
  for model in "${MODELS[@]}"; do
    CURRENT_RUN=$((CURRENT_RUN + 1))

    logBatch ''
    logBatch '****************************************************************'
    logBatch "--- ▶️ Run $CURRENT_RUN/$TOTAL_RUNS"
    logBatch "--- 📝 Prompt : $promptID"
    logBatch "--- 🤖 Model  : $model"
    logBatch '--- ⏳ Launching experiments.py ...'

    args=(
      --input-csv "$INPUT_CSV"
      --model "$model"
      --prompt-id "$promptID"
      --output-folder "$OUTPUT_ROOT"
    )

    runStartEpoch="$(date +%s)"
    if "$PYTHON_BIN" "$EXPERIMENT_SCRIPT" "${args[@]}" >> "$LOGS_FULL" 2>&1
    then
      runEndEpoch="$(date +%s)"
      runElapsedSeconds=$((runEndEpoch - runStartEpoch))
      runElapsedHours=$((runElapsedSeconds / 3600))
      runElapsedMinutes=$(((runElapsedSeconds % 3600) / 60))
      runElapsedRemainderSeconds=$((runElapsedSeconds % 60))
      logBatch "--- ✅ Completed: prompt=$promptID | model=$model | elapsed=${runElapsedHours}h ${runElapsedMinutes}m ${runElapsedRemainderSeconds}s (${runElapsedSeconds}s)"
    else
      exitCode=$?
      runEndEpoch="$(date +%s)"
      runElapsedSeconds=$((runEndEpoch - runStartEpoch))
      runElapsedHours=$((runElapsedSeconds / 3600))
      runElapsedMinutes=$(((runElapsedSeconds % 3600) / 60))
      runElapsedRemainderSeconds=$((runElapsedSeconds % 60))
      logBatch "--- ❌ Failed   : prompt=$promptID | model=$model | elapsed=${runElapsedHours}h ${runElapsedMinutes}m ${runElapsedRemainderSeconds}s (${runElapsedSeconds}s) | exitCode=$exitCode"
    fi
  done
done

batchEndEpoch="$(date +%s)"
batchEndTime="$(date '+%Y-%m-%d %H:%M:%S')"
elapsedSeconds=$((batchEndEpoch - batchStartEpoch))
elapsedHours=$((elapsedSeconds / 3600))
elapsedMinutes=$(((elapsedSeconds % 3600) / 60))
elapsedRemainderSeconds=$((elapsedSeconds % 60))

# Final batch summary
logBatch ''
logBatch '++++++++++++++++++++++++++++++++++++++++++++++++++++'
logBatch '+++ ⭐ FINISHED BATCH EXECUTION ⭐ +++'
logBatch "--> 🕒 Batch End Time   : $batchEndTime "
logBatch "--> ⏱️ Elapsed Time     : ${elapsedHours}h ${elapsedMinutes}m ${elapsedRemainderSeconds}s (${elapsedSeconds}s)"
