#!/bin/bash
# ==============================================================================
# GDB Debugging Script for face_analysis_cli with Hooks
#
# This script simplifies the process of debugging the face_analysis_cli
# executable with GDB, automatically setting breakpoints based on a
# hook configuration file.
#
# It handles PIE (Position-Independent Executable) by calculating the
# executable's base address at runtime and applying hook offsets.
#
# Usage:
# ./scripts/debug_with_gdb.sh <path_to_model_file> <path_to_image>
#
# Example:
# ./scripts/debug_with_gdb.sh resources/models/Pikachu resources/images/test_image.jpg
#
# Prerequisites:
# - gdb: The GNU Debugger.
# - jq: A command-line JSON processor (for parsing the hook config).
# - nm: For reading symbol information from the executable.
# ==============================================================================

set -eo pipefail

# --- Pre-run Checks for Dependencies ---
if ! command -v gdb &> /dev/null; then
    echo "Error: 'gdb' is not installed or not in your PATH. Please install it to continue."
    exit 1
fi
if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is not installed or not in your PATH. Please install it (e.g., 'brew install jq' or 'sudo apt-get install jq')."
    exit 1
fi
if ! command -v nm &> /dev/null; then
    echo "Error: 'nm' is not installed or not in your PATH. It's part of standard build tools (like Binutils or Xcode Command Line Tools)."
    exit 1
fi


# --- Argument Validation ---
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <path_to_model_file> <path_to_image>"
    exit 1
fi

MODEL_PATH_ARG="$1"
IMAGE_PATH_ARG="$2"

# --- Configuration ---
# Base directory of the project, determined relative to the script's location
BASE_DIR=$(realpath "$(dirname "$0")/..")

# --- Target Specific Configuration ---
EXECUTABLE_PATH="$BASE_DIR/resources/execution_files/face_analysis_cli"
HOOK_CONFIG_DIR="$BASE_DIR/hook_config"
EXECUTABLE_NAME=$(basename "$EXECUTABLE_PATH")
HOOK_CONFIG_PATH="$HOOK_CONFIG_DIR/${EXECUTABLE_NAME}_hook_config.json"

# --- Pre-run Checks & Setup ---
if [ ! -f "$MODEL_PATH_ARG" ]; then
    echo "Error: Model file not found at '$MODEL_PATH_ARG'"
    exit 1
fi
if [ ! -f "$IMAGE_PATH_ARG" ]; then
    echo "Error: Image file not found at '$IMAGE_PATH_ARG'"
    exit 1
fi
if [ ! -f "$EXECUTABLE_PATH" ]; then
    echo "Error: Executable '$EXECUTABLE_PATH' not found."
    exit 1
fi
if [ ! -f "$HOOK_CONFIG_PATH" ]; then
    echo "Error: Hooks file not found at '$HOOK_CONFIG_PATH'"
    exit 1
fi

# --- Environment Setup for Shared Libraries ---
echo "Setting up LD_LIBRARY_PATH..."
export LD_LIBRARY_PATH=$BASE_DIR/third_party/mnn/lib:$BASE_DIR/third_party/onnxruntime/lib:$BASE_DIR/third_party/InspireFace/lib:$LD_LIBRARY_PATH

# Create a temporary directory for generated files
OUTPUT_DIR=$(mktemp -d)
# Setup a trap to clean up the temporary directory on script exit
trap 'echo "Cleaning up temporary directory..."; rm -rf -- "$OUTPUT_DIR"' EXIT

# --- Pre-debug Step: Generate feature file ---
FEATURE_FILE_PATH="$OUTPUT_DIR/feature.bin"
echo "----------------------------------------------------"
echo "Generating feature file for image..."
echo "Command: $EXECUTABLE_PATH \"$MODEL_PATH_ARG\" extract \"$IMAGE_PATH_ARG\" \"$FEATURE_FILE_PATH\""

"$EXECUTABLE_PATH" "$MODEL_PATH_ARG" extract "$IMAGE_PATH_ARG" "$FEATURE_FILE_PATH"

if [ ! -f "$FEATURE_FILE_PATH" ]; then
    echo "Error: Failed to generate feature file. Aborting."
    exit 1
fi
echo "Feature file generated at: $FEATURE_FILE_PATH"
echo "----------------------------------------------------"


# --- Generate GDB Script ---
GDB_SCRIPT_PATH="$OUTPUT_DIR/gdb_commands.gdb"
echo "Generating GDB initialization script at: $GDB_SCRIPT_PATH"

# Get the offset of the 'main' symbol from the executable file
# This is used to calculate the PIE slide (base address) once in memory
MAIN_SYMBOL_OFFSET=$(nm "$EXECUTABLE_PATH" | grep ' T main' | awk '{print "0x"$1}')
if [ -z "$MAIN_SYMBOL_OFFSET" ]; then
    echo "Warning: Could not determine 'main' symbol offset. Breakpoints may be incorrect if PIE is enabled."
    MAIN_SYMBOL_OFFSET="0x0" # Default to 0 to avoid script errors
fi
echo "Found 'main' symbol offset at: $MAIN_SYMBOL_OFFSET"

# Use a heredoc to write the Python GDB script.
# The 'EOF' is quoted to prevent shell variable expansion inside the heredoc.
cat <<'EOF' > "$GDB_SCRIPT_PATH"
python
import gdb
import json
import os
import re

# These values are passed from the bash script
HOOK_CONFIG_PATH = os.environ.get("HOOK_CONFIG_PATH")
MAIN_SYMBOL_OFFSET_STR = os.environ.get("MAIN_SYMBOL_OFFSET")

def set_hooks():
    if not HOOK_CONFIG_PATH or not os.path.exists(HOOK_CONFIG_PATH):
        print(f"[GDB Script] Error: HOOK_CONFIG_PATH env var not set or file does not exist: {HOOK_CONFIG_PATH}")
        return

    if not MAIN_SYMBOL_OFFSET_STR:
        print("[GDB Script] Error: MAIN_SYMBOL_OFFSET env var not set.")
        return

    main_symbol_offset = int(MAIN_SYMBOL_OFFSET_STR, 16)

    # Temporarily break at main to find the runtime address
    bp = gdb.Breakpoint("main", temporary=True)
    gdb.execute("run")

    # Get the address of the main function frame
    frame = gdb.selected_frame()
    main_addr = frame.pc()

    # Calculate PIE base address (slide)
    pie_slide = main_addr - main_symbol_offset
    print(f"[GDB Script] 'main' is at {hex(main_addr)}, file offset is {hex(main_symbol_offset)}")
    print(f"[GDB Script] Calculated PIE slide (base address): {hex(pie_slide)}")

    # Load hooks and set breakpoints
    print("[GDB Script] Setting breakpoints from hook config...")
    with open(HOOK_CONFIG_PATH, 'r') as f:
        hooks = json.load(f)

    for hook in hooks:
        offset = int(hook["address"], 16)
        bp_addr = pie_slide + offset
        gdb.execute(f"break *{hex(bp_addr)}")
        print(f"  - Breakpoint set at {hex(bp_addr)} (offset {hex(offset)}) for instruction '{hook.get('original_branch_instruction', 'N/A')}'")
    
    print("[GDB Script] All hooks set. Program is at 'main'. Use 'continue' to proceed.")

# Run the setup function
set_hooks()

end
EOF

# --- Run GDB ---
echo "----------------------------------------------------"
echo "Starting GDB session..."
echo "The GDB script will run, set breakpoints, and leave you at the 'main' function."
echo "Use GDB commands like 'c' (continue), 'n' (next), 'si' (step instruction) to debug."
echo "----------------------------------------------------"

# Export variables needed by the GDB python script
export HOOK_CONFIG_PATH
export MAIN_SYMBOL_OFFSET

# Launch GDB
# -q: quiet start
# -x: execute script
# --args: pass arguments to the target executable
gdb -q -x "$GDB_SCRIPT_PATH" --args "$EXECUTABLE_PATH" "$MODEL_PATH_ARG" analyze "$IMAGE_PATH_ARG" "$FEATURE_FILE_PATH"

echo "GDB session finished." 