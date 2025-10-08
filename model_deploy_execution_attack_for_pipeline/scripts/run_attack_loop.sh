#!/bin/bash

# --- Path Definitions ---
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

# --- Core Attack Settings ---
# Directory containing all images to attack. The script will iterate through all .jpg files here.
IMAGE_DIR="$PROJECT_ROOT/filtered_images"
ITERATIONS=100
LEARNING_RATE=1.5
L_INF_NORM=20.0

# --- NES Specific Settings ---
# POPULATION_SIZE is now calculated as NUM_WORKERS * POP_MULTIPLIER.
# Adjust the multiplier to control the population size.
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
# The gdbserver kill command is now moved inside the loop.

# Kill any lingering frida-server processes
adb shell 'su -c "pkill -f -u root frida"' > /dev/null 2>&1 && echo "[+] Killed lingering frida-server processes on device." || echo "[+] No lingering frida-server processes found on device."

# Start a fresh frida-server in the background
echo "[+] Starting frida-server in the background..."
adb shell 'su -c "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"'
echo "[+] Waiting for frida-server to initialize..."
sleep 2 # Give frida-server a moment to start up

PYTHON_SCRIPT_PATH="$PROJECT_ROOT/src/attackers/nes_attack_android_parallel.py"

# --- Print Configuration and Run ---
echo "[+] Starting the PARALLEL NES Attack Orchestrator for Android..."
# (Configuration printing remains the same)
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
echo "    - Iterations:           $ITERATIONS"
echo "    - Learning Rate:        $LEARNING_RATE"
echo "    - L-inf Norm:           $L_INF_NORM"
echo "    - Image Directory:      $IMAGE_DIR"
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
# (Argument building logic remains the same)
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


# --- Execute the Attack for each image in the directory ---
echo "[+] Starting attack iteration over directory: $IMAGE_DIR"
for IMAGE_PATH in "$IMAGE_DIR"/*.jpg; do
    # Check if the file exists and is a regular file
    if [ ! -f "$IMAGE_PATH" ]; then
        echo "[-] No .jpg files found in $IMAGE_DIR. Skipping loop."
        continue
    fi
    
    echo "----------------------------------------------------"
    echo "[+] Processing image: $(basename "$IMAGE_PATH")"
    
    # Kill existing processes before each new attack to prevent port conflicts
    echo "[+] Killing previous gdbserver processes..."
    adb shell "su -c 'pkill gdbserver'" > /dev/null 2>&1 || true
    echo "[+] Killing previous AIDL processes..."
    adb shell 'su -c "pkill -f -u root aidl"' || true
    
    # Create a unique output directory for the current image's attack
    # The directory name will be based on the image's filename
    OUTPUT_DIR="$PROJECT_ROOT/outputs_ancface/$(basename "$IMAGE_PATH" .jpg)_attack_$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    echo "[+] Attack outputs for this image will be saved to: $OUTPUT_DIR"

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
    echo "[+] Attack for $(basename "$IMAGE_PATH") finished."
    echo "[+] Pausing for 2 seconds before the next image..."
    sleep 2
done

echo "----------------------------------------------------"
echo "[+] All images have been processed. Script completed."
echo "----------------------------------------------------"