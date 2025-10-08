#!/bin/bash

# This script configures and runs the frida_gdb_orchestrator.py script.
# All configurations are set in this file for easy modification.

# --- Configuration ---

# Set the project root directory relative to this script's location.
# This makes the script runnable from any directory.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd)

# Target process to be spawned on the device.
TARGET_PROCESS="/vendor/bin/hw/android.hardware.biometrics.face-service.aidl"

# Path to the image that will be sent to the process to trigger the functions.
IMAGE_PATH="$PROJECT_ROOT/dataset/test1.jpg"

# Path to the hook configuration JSON file.
HOOK_CONFIG="$PROJECT_ROOT/frida_gdb_orchestrator/config.json"

# Port for the gdbserver to listen on the device. This port will be forwarded to the host.
GDB_PORT=12345

# Full path to the GDB client executable.
#
# Note: Using '~' requires the shell to expand it. Double-quoting prevents this,
# so we use $HOME or keep it unquoted if the path is static.
GDB_CLIENT="$HOME/Library/Android/sdk/ndk/22.1.7171670/prebuilt/darwin-x86_64/bin/gdb"

# The name of the shared library (.so) to find the base address for.
# Breakpoint offsets in the hook config are relative to this library's base address.
BASE_SYMBOL="libanc_faceid.so"


# --- Execution ---

# Check if the GDB client executable exists.
if [ ! -f "$GDB_CLIENT" ]; then
    echo "[Error] GDB client not found at: $GDB_CLIENT"
    echo "Please update the GDB_CLIENT path in this script."
    exit 1
fi

# Construct the command to run the orchestrator script.
# We use full paths to ensure the script can be run from anywhere.
PYTHON_SCRIPT_PATH="$PROJECT_ROOT/frida_gdb_orchestrator/frida_gdb_orchestrator.py"

echo "[+] Starting the Frida GDB Orchestrator..."
echo "    - Target Process: $TARGET_PROCESS"
echo "    - Image Path:     $IMAGE_PATH"
echo "    - Hook Config:    $HOOK_CONFIG"
echo "    - GDB Port:       $GDB_PORT"
echo "    - GDB Client:     $GDB_CLIENT"
echo "    - Base Symbol:    $BASE_SYMBOL"
echo "----------------------------------------------------"

python3 "$PYTHON_SCRIPT_PATH" \
    --target-process "$TARGET_PROCESS" \
    --image-path "$IMAGE_PATH" \
    --hook-config "$HOOK_CONFIG" \
    --gdb-port "$GDB_PORT" \
    --gdb-client "$GDB_CLIENT" \
    --base-symbol "$BASE_SYMBOL"

echo "----------------------------------------------------"
echo "[+] Orchestrator script finished."
