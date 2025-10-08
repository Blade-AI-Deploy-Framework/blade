#!/bin/bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd)

# --- Parallelism ---
NUM_WORKERS=8
NUM_RESTARTS=1 # Number of random restarts to run

# --- Frida/GDB Orchestrator Settings ---
TARGET_PROCESS="/vendor/bin/hw/android.hardware.biometrics.face-service.aidl"
BASE_SYMBOL="libanc_faceid.so"
HOOK_CONFIG="$PROJECT_ROOT/frida_gdb_orchestrator/config.json"
GDB_PORT=12345
# IMPORTANT: Update this path to your actual NDK GDB location
GDB_CLIENT="$HOME/Library/Android/sdk/ndk/22.1.7171670/prebuilt/darwin-x86_64/bin/gdb"

IMAGE_PATH="$PROJECT_ROOT/dataset/01.jpg"

OUTPUT_DIR="$PROJECT_ROOT/outputs/nes_android_parallel_attack_$(date +%Y%m%d-%H%M%S)"
ITERATIONS=100
LEARNING_RATE=1.5
L_INF_NORM=20.0

POP_MULTIPLIER=8
POPULATION_SIZE=$((NUM_WORKERS * POP_MULTIPLIER)) 
INITIAL_SIGMA=3
ENABLE_FITNESS_SHAPING=true # Use ranking-based fitness shaping to stabilize gradients

# --- Stagnation-based Decay Settings ---
ENABLE_STAGNATION_DECAY=true
LR_DECAY_RATE=0.95
STAGNATION_PATIENCE=10
MIN_LOSS_DELTA=0.001
LR_DECAY_STEPS=20

# --- Dynamic Focus Strategy Settings ---
ENABLE_DYNAMIC_FOCUS=true
EVALUATION_WINDOW=10
BOOST_WEIGHT=5.0
NON_TARGET_WEIGHT=1.0
SATISFIED_WEIGHT=3.0
SATISFACTION_PATIENCE=3

# --- Gradient Stabilization & Perturbation Settings ---
# USE_SIGNED_GRAD=false
USE_GRADIENT_NORMALIZATION=true
ATTACK_Y_CHANNEL_ONLY=true

# --- Pre-flight Checks ---
if [ ! -f "$GDB_CLIENT" ]; then
    echo "[Error] GDB client not found at: $GDB_CLIENT"
    echo "Please update the GDB_CLIENT path in this script."
    exit 1
fi

# --- Environment Setup ---
echo "[+] Performing pre-run cleanup..."
adb forward --remove-all
adb shell "su -c 'pkill gdbserver'" > /dev/null 2>&1 && echo "[+] Killed lingering gdbserver processes on device." || echo "[+] No lingering gdbserver processes found on device."

mkdir -p "$OUTPUT_DIR"
echo "[+] Attack outputs will be saved to: $OUTPUT_DIR"

PYTHON_SCRIPT_PATH="$PROJECT_ROOT/src/attackers/nes_attack_android_parallel.py"

# --- Print Configuration and Run ---
echo "[+] Starting the PARALLEL NES Attack Orchestrator for Android..."
echo "----------------------------------------------------"
echo "  Parallelism:"
echo "    - Workers:            $NUM_WORKERS"
echo "    - Restarts:           $NUM_RESTARTS"
echo "  Remote Target:"
echo "    - Process:            $TARGET_PROCESS"
echo "    - Base Library:         $BASE_SYMBOL"
echo "    - Hook Config:          $HOOK_CONFIG"
echo "    - GDB Base Port:        $GDB_PORT"
echo "  Attack Parameters:"
echo "    - Initial Image:        $IMAGE_PATH"
echo "    - Iterations:           $ITERATIONS"
echo "    - Learning Rate:        $LEARNING_RATE"
echo "    - L-inf Norm:           $L_INF_NORM"
echo "  NES Parameters:"
echo "    - Population Size:      $POPULATION_SIZE ($NUM_WORKERS workers x $POP_MULTIPLIER multiplier)"
echo "    - Initial Sigma:        $INITIAL_SIGMA"
echo "    - Fitness Shaping:      $ENABLE_FITNESS_SHAPING"
echo "  Dynamic Focus:"
echo "    - Enabled:              $ENABLE_DYNAMIC_FOCUS"
echo "  Stabilization:"
echo "    - Use Signed Grad:      $USE_SIGNED_GRAD"
echo "  Perturbation:"
echo "    - Y-Channel Only:       $ATTACK_Y_CHANNEL_ONLY"
echo "----------------------------------------------------"

# --- Build Dynamic Arguments ---
DYNAMIC_FOCUS_ARGS=()
if [ "$ENABLE_DYNAMIC_FOCUS" = true ]; then
    DYNAMIC_FOCUS_ARGS+=(--enable-dynamic-focus)
    DYNAMIC_FOCUS_ARGS+=(--evaluation-window "$EVALUATION_WINDOW")
    DYNAMIC_FOCUS_ARGS+=(--boost-weight "$BOOST_WEIGHT")
    DYNAMIC_FOCUS_ARGS+=(--non-target-weight "$NON_TARGET_WEIGHT")
    DYNAMIC_FOCUS_ARGS+=(--satisfied-weight "$SATISFIED_WEIGHT")
    DYNAMIC_FOCUS_ARGS+=(--satisfaction-patience "$SATISFACTION_PATIENCE")
fi

STAGNATION_ARGS=()
if [ "$ENABLE_STAGNATION_DECAY" = true ]; then
    STAGNATION_ARGS+=(--enable-stagnation-decay)
    STAGNATION_ARGS+=(--lr-decay-rate "$LR_DECAY_RATE")
    STAGNATION_ARGS+=(--stagnation-patience "$STAGNATION_PATIENCE")
    STAGNATION_ARGS+=(--min-loss-delta "$MIN_LOSS_DELTA")
    STAGNATION_ARGS+=(--lr-decay-steps "$LR_DECAY_STEPS")
fi

STABILIZATION_ARGS=()
if [ "$USE_SIGNED_GRAD" = true ]; then
    STABILIZATION_ARGS+=(--use-signed-grad)
fi
if [ "$USE_GRADIENT_NORMALIZATION" = true ]; then
    STABILIZATION_ARGS+=(--use-gradient-normalization)
fi

PERTURBATION_ARGS=()
if [ "$ATTACK_Y_CHANNEL_ONLY" = true ]; then
    PERTURBATION_ARGS+=(--attack-y-channel-only)
fi

NES_ARGS=()
if [ "$ENABLE_FITNESS_SHAPING" = true ]; then
    NES_ARGS+=(--enable-fitness-shaping)
fi

# --- Execute the Attack ---
python3 "$PYTHON_SCRIPT_PATH" \
    --num-workers "$NUM_WORKERS" \
    --num-restarts "$NUM_RESTARTS" \
    --target-process "$TARGET_PROCESS" \
    --base-symbol "$BASE_SYMBOL" \
    --hooks "$HOOK_CONFIG" \
    --gdb-port "$GDB_PORT" \
    --gdb-client "$GDB_CLIENT" \
    --image "$IMAGE_PATH" \
    --output-dir "$OUTPUT_DIR" \
    --iterations "$ITERATIONS" \
    --learning-rate "$LEARNING_RATE" \
    --l-inf-norm "$L_INF_NORM" \
    --population-size "$POPULATION_SIZE" \
    --sigma "$INITIAL_SIGMA" \
    "${NES_ARGS[@]}" \
    "${DYNAMIC_FOCUS_ARGS[@]}" \
    "${STAGNATION_ARGS[@]}" \
    "${STABILIZATION_ARGS[@]}" \
    "${PERTURBATION_ARGS[@]}"

echo "----------------------------------------------------"
echo "[+] Attack script finished."
echo "[+] Outputs are in: $OUTPUT_DIR"
echo "----------------------------------------------------"

# --- Summary ---
echo
echo "--- Attack Summary ---"
CSV_FILE=$(find "$OUTPUT_DIR" -maxdepth 1 -name "*.csv" | head -n 1)

if [ -z "$CSV_FILE" ]; then
    echo "Could not find CSV log file in $OUTPUT_DIR to generate summary."
    exit 0
fi

echo "Parsing results from: $(basename "$CSV_FILE")"
echo
printf "%-10s | %-12s | %-15s | %-18s | %-12s\n" "Restart" "Result" "Final Loss" "Hooks Satisfied" "Iterations"
echo "--------------------------------------------------------------------------------------------"

OVERALL_SUCCESS=false

for i in $(seq 1 $NUM_RESTARTS); do
    LAST_LINE=$(grep "^${i}," "$CSV_FILE" | tail -n 1)

    if [ -z "$LAST_LINE" ]; then
        # This restart did not run, likely because a previous one succeeded
        continue
    fi
    
    # Using awk for robust CSV parsing
    RESTART_NUM=$(echo "$LAST_LINE" | awk -F, '{print $1}')
    ITERATIONS=$(echo "$LAST_LINE" | awk -F, '{print $2}')
    LOSS=$(echo "$LAST_LINE" | awk -F, '{print $4}')
    SATISFIED=$(echo "$LAST_LINE" | awk -F, '{print $8}')
    TOTAL_HOOKS=$(echo "$LAST_LINE" | awk -F, '{print $9}')
    SUCCESS=$(echo "$LAST_LINE" | awk -F, '{print $15}')

    if [ "$SUCCESS" = "True" ]; then
        RESULT="SUCCESS"
        OVERALL_SUCCESS=true
    else
        RESULT="FAIL"
    fi
    
    printf "%-10s | %-12s | %-15s | %-18s | %-12s\n" "$RESTART_NUM" "$RESULT" "$LOSS" "$SATISFIED / $TOTAL_HOOKS" "$ITERATIONS"

done
echo "--------------------------------------------------------------------------------------------"
echo

if [ "$OVERALL_SUCCESS" = true ]; then
    echo "[+] Overall result: SUCCESS! An effective adversarial image was generated."
    echo "[+] Best image saved to: $OUTPUT_DIR/best_attack_image_nes_parallel.png"
    echo "[+] Successful image saved to: $OUTPUT_DIR/successful_attack_image_nes_parallel.png"
else
    echo "[-] Overall result: FAIL. The attack did not succeed in any of the restarts."
    echo "[-] Best attempt saved to: $OUTPUT_DIR/best_attack_image_nes_parallel.png"
fi
echo
