#!/bin/bash

# --- Path Definitions ---
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd)

# --- Target Images ---
# A specific list of image basenames (without .jpg extension) to attack.
TARGET_IMAGES=(
    "n003148-0488_01" "n006655-0213_01" "n002059-0088_01" "n002665-0059_01"
    "n003719-0097_01" "n005643-0309_01" "n000737-0175_01" "n001041-0146_01"
    "n001210-0066_01" "n001425-0003_01" "n001476-0329_01" "n001568-0299_01"
    "n001642-0228_01" "n001645-0325_01" "n001700-0598_02" "n002094-0141_01"
    "n002125-0105_01" "n002254-0159_01" "n002584-0361_01" "n002774-0084_01"
    "n002919-0110_01" "n003004-0126_01" "n003114-0197_01" "n003310-0100_01"
    "n004301-0430_01" "n005012-0059_01" "n005610-0137_01" "n006033-0080_01"
    "n006238-0025_01" "n006265-0410_01" "n006696-0180_01" "n006696-0318_01"
    "n007311-0032_01" "n007342-0162_01" "n007926-0480_01"
)

IMAGE_SOURCE_DIR="$PROJECT_ROOT/filtered_images" # Directory where the original images are stored.

# --- Parallelism ---
NUM_WORKERS=8
NUM_RESTARTS=1

# --- Frida/GDB Orchestrator Settings ---
TARGET_PROCESS="/vendor/bin/hw/android.hardware.biometrics.face-service.aidl"
BASE_SYMBOL="libanc_faceid.so"
HOOK_CONFIG="$PROJECT_ROOT/frida_gdb_orchestrator/config.json"
GDB_PORT=12345
GDB_CLIENT="$HOME/Library/Android/sdk/ndk/22.1.7171670/prebuilt/darwin-x86_64/bin/gdb"

# --- Core Attack Settings ---
ITERATIONS=150
LEARNING_RATE=1.5
L_INF_NORM=20.0

# --- NES Specific Settings ---
POP_MULTIPLIER=8
POPULATION_SIZE=$((NUM_WORKERS * POP_MULTIPLIER)) 
INITIAL_SIGMA=10
ENABLE_FITNESS_SHAPING=true

# --- Stagnation-based Decay Settings ---
ENABLE_STAGNATION_DECAY=true
LR_DECAY_RATE=0.97
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
USE_GRADIENT_NORMALIZATION=true
ATTACK_Y_CHANNEL_ONLY=true

# --- Pre-flight Checks ---
if [ ! -f "$GDB_CLIENT" ]; then
    echo "[Error] GDB client not found at: $GDB_CLIENT"
    exit 1
fi

# --- Environment Setup ---
echo "[+] Performing pre-run cleanup..."
adb forward --remove-all
adb shell 'su -c "pkill -f -u root frida"' > /dev/null 2>&1 && echo "[+] Killed lingering frida-server." || echo "[+] No lingering frida-server found."
echo "[+] Starting frida-server..."
adb shell 'su -c "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"'
sleep 2 

PYTHON_SCRIPT_PATH="$PROJECT_ROOT/src/attackers/nes_attack_android_parallel.py"

# --- Print Configuration ---
echo "[+] Starting the PARALLEL NES Attack for a SPECIFIC LIST of images..."
echo "----------------------------------------------------"
echo "  Total Images to Process: ${#TARGET_IMAGES[@]}"
# ... (rest of the configuration printing is similar to the original script)
echo "----------------------------------------------------"

# --- Build Dynamic Arguments ---
DYNAMIC_FOCUS_ARGS=()
if [ "$ENABLE_DYNAMIC_FOCUS" = true ]; then
    DYNAMIC_FOCUS_ARGS+=(--enable-dynamic-focus --evaluation-window "$EVALUATION_WINDOW" --boost-weight "$BOOST_WEIGHT" --non-target-weight "$NON_TARGET_WEIGHT" --satisfied-weight "$SATISFIED_WEIGHT" --satisfaction-patience "$SATISFACTION_PATIENCE")
fi
STAGNATION_ARGS=()
if [ "$ENABLE_STAGNATION_DECAY" = true ]; then
    STAGNATION_ARGS+=(--enable-stagnation-decay --lr-decay-rate "$LR_DECAY_RATE" --stagnation-patience "$STAGNATION_PATIENCE" --min-loss-delta "$MIN_LOSS_DELTA" --lr-decay-steps "$LR_DECAY_STEPS")
fi
STABILIZATION_ARGS=()
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

# --- Execute the Attack for each image in the list ---
echo "[+] Starting attack iteration for the specified list of images."
for IMAGE_BASENAME in "${TARGET_IMAGES[@]}"; do
    IMAGE_PATH="$IMAGE_SOURCE_DIR/$IMAGE_BASENAME.jpg"
    
    if [ ! -f "$IMAGE_PATH" ]; then
        echo "[-] WARNING: Image not found, skipping: $IMAGE_PATH"
        continue
    fi
    
    echo "----------------------------------------------------"
    echo "[+] Processing image: $(basename "$IMAGE_PATH")"
    
    echo "[+] Killing previous gdbserver and AIDL processes..."
    adb shell "su -c 'pkill gdbserver'" > /dev/null 2>&1 || true
    adb shell 'su -c "pkill -f -u root android.hardware.biometrics.face-service.aidl"' || true
    
    OUTPUT_DIR="$PROJECT_ROOT/outputs_ancface_4/$(basename "$IMAGE_PATH" .jpg)_attack_$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$OUTPUT_DIR"
    echo "[+] Attack outputs will be saved to: $OUTPUT_DIR"

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
    echo "[+] Pausing for 2 seconds..."
    sleep 2
done

echo "----------------------------------------------------"
echo "[+] All specified images have been processed. Script completed."
echo "----------------------------------------------------"
