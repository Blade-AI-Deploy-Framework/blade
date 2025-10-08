#!/bin/bash

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd)

# Define the directory containing the images to be attacked
IMAGE_DIR="$PROJECT_ROOT/filtered_images"

# --- Main Configuration (same as the single-run script) ---
NUM_WORKERS=8

TARGET_PROCESS="/vendor/bin/hw/android.hardware.biometrics.face-service.aidl"
BASE_SYMBOL="libanc_faceid.so"
HOOK_CONFIG="$PROJECT_ROOT/frida_gdb_orchestrator/config.json"
GDB_PORT=12345
GDB_CLIENT="$HOME/Library/Android/sdk/ndk/22.1.7171670/prebuilt/darwin-x86_64/bin/gdb"

ITERATIONS=50
LEARNING_RATE=2
L_INF_NORM=255.0
SPSA_C=0.1
SAMPLES_PER_WORKER=8
SPSA_GRAD_SAMPLES=$((NUM_WORKERS * SAMPLES_PER_WORKER))

ENABLE_STAGNATION_DECAY=true
LR_DECAY_RATE=0.97
STAGNATION_PATIENCE=10
MIN_LOSS_DELTA=0.001

ENABLE_DYNAMIC_FOCUS=true
EVALUATION_WINDOW=7
BOOST_WEIGHT=5
NON_TARGET_WEIGHT=1
SATISFIED_WEIGHT=3.0
SATISFACTION_PATIENCE=3

USE_SIGNED_GRAD=false
ATTACK_Y_CHANNEL_ONLY=true
# --- End of Configuration ---

# --- Pre-flight Checks ---
if [ ! -d "$IMAGE_DIR" ]; then
    echo "[Error] Image directory not found at: $IMAGE_DIR"
    exit 1
fi

if [ ! -f "$GDB_CLIENT" ]; then
    echo "[Error] GDB client not found at: $GDB_CLIENT"
    echo "Please update the GDB_CLIENT path in this script."
    exit 1
fi

# --- Main Attack Loop ---
echo "[+] Starting batch attack for all JPG images in: $IMAGE_DIR"

for IMAGE_PATH in "$IMAGE_DIR"/*.jpg; do
    # Check if any jpg files were found
    [ -e "$IMAGE_PATH" ] || { echo "[Warning] No .jpg files found in '$IMAGE_DIR'. Exiting."; break; }

    IMAGE_BASENAME=$(basename "$IMAGE_PATH" .jpg)
    OUTPUT_DIR="$PROJECT_ROOT/outputs/spsa_batch_${IMAGE_BASENAME}_$(date +%Y%m%d-%H%M%S)"

    echo ""
    echo "========================================================"
    echo "          STARTING ATTACK FOR: $IMAGE_BASENAME"
    echo "========================================================"
    
    # Perform pre-run cleanup for each individual attack
    echo "[+] Performing pre-run cleanup for this image..."
    adb forward --remove-all > /dev/null 2>&1
    adb shell "su -c 'pkill gdbserver'" > /dev/null 2>&1 && echo "[+] Killed lingering gdbserver processes on device." || echo "[+] No lingering gdbserver processes found on device."
    
    mkdir -p "$OUTPUT_DIR"
    echo "[+] Attack outputs will be saved to: $OUTPUT_DIR"

    PYTHON_SCRIPT_PATH="$PROJECT_ROOT/src/attackers/spsa_attack_android_parallel.py"
    
    echo "[+] Launching Python orchestrator..."

    # --- Argument Assembly (same as the single-run script) ---
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
    fi

    STABILIZATION_ARGS=()
    if [ "$USE_SIGNED_GRAD" = true ]; then
        STABILIZATION_ARGS+=(--use-signed-grad)
    fi
    
    PERTURBATION_ARGS=()
    if [ "$ATTACK_Y_CHANNEL_ONLY" = true ]; then
        PERTURBATION_ARGS+=(--attack-y-channel-only)
    fi

    # --- Execute the Attack ---
    python3 "$PYTHON_SCRIPT_PATH" \
        --num-workers "$NUM_WORKERS" \
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
        --spsa-c "$SPSA_C" \
        --spsa-grad-samples "$SPSA_GRAD_SAMPLES" \
        "${DYNAMIC_FOCUS_ARGS[@]}" \
        "${STAGNATION_ARGS[@]}" \
        "${STABILIZATION_ARGS[@]}" \
        "${PERTURBATION_ARGS[@]}"

    echo "----------------------------------------------------"
    echo "[+] Attack script finished for '$IMAGE_BASENAME'."
    echo "[+] Outputs are in: $OUTPUT_DIR"
    
    # Optional: Add a small delay between attacks to let the device cool down or stabilize
    # echo "[+] Waiting for 5 seconds before next attack..."
    # sleep 5
done

echo ""
echo "========================================================"
echo "          ALL IMAGES PROCESSED. BATCH ATTACK COMPLETE."
echo "========================================================"
