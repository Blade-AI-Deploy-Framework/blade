#!/bin/bash

# A simple wrapper to execute GDB on the host machine for the attack script.
# It sets up library paths and executes GDB with the correct arguments.

# --- Validation ---
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <abs_path_to_executable> <abs_path_to_model> <abs_path_to_image>" >&2
    exit 1
fi

# --- Path Setup ---
# Get the absolute path to the directory containing this script.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="${SCRIPT_DIR}/../.." # Go up to the project root from src/attackers

# Define paths to the required libraries and scripts relative to the project root.
MNN_LIB_PATH="${PROJECT_ROOT}/third_party/mnn/lib"
ONNX_LIB_PATH="${PROJECT_ROOT}/third_party/onnxruntime/lib"
INSPIRE_LIB_PATH="${PROJECT_ROOT}/third_party/InspireFace/lib"
GDB_SCRIPT_PATH="${SCRIPT_DIR}/gdb_script_host.py" # Use the new host-specific GDB script

# The executable and its arguments are passed from the Python script.
# The last argument is now designated as the hooks file.
all_args=("$@")
num_args=${#all_args[@]}

if [ "$num_args" -lt 4 ]; then
    echo "Usage: $0 <abs_path_to_executable> <model_path_1> ... <model_path_n> <abs_path_to_image> <abs_path_to_hooks_json>" >&2
    exit 1
fi

# The hooks file is the last argument.
hooks_path_idx=$((num_args - 1))
export HOOKS_JSON_PATH="${all_args[$hooks_path_idx]}"

# All arguments before the last one are for the program being debugged.
executable_and_args=("${all_args[@]:0:$hooks_path_idx}")
EXECUTABLE_PATH="${executable_and_args[0]}"

# --- Pre-run Checks ---
if [ ! -f "${GDB_SCRIPT_PATH}" ]; then
    echo "Error: GDB script not found at ${GDB_SCRIPT_PATH}" >&2
    exit 1
fi
for lib_path in "${MNN_LIB_PATH}" "${ONNX_LIB_PATH}" "${INSPIRE_LIB_PATH}"; do
    if [ ! -d "$lib_path" ]; then
        echo "Warning: Library directory not found: $lib_path" >&2
    fi
done


# --- Execution ---
# Set the LD_LIBRARY_PATH to include our custom-built libraries so the executable can find them.
# Then, execute GDB in batch mode, running the Python gdb script.
# The --args flag passes all subsequent arguments to the program being debugged.
echo "Running GDB with script: ${GDB_SCRIPT_PATH}"
echo "Executable and args: ${executable_and_args[@]}"
echo "Using hooks file from env: ${HOOKS_JSON_PATH}"
echo "Using LD_LIBRARY_PATH: ${MNN_LIB_PATH}:${ONNX_LIB_PATH}:${INSPIRE_LIB_PATH}"

LD_LIBRARY_PATH="${MNN_LIB_PATH}:${ONNX_LIB_PATH}:${INSPIRE_LIB_PATH}:${LD_LIBRARY_PATH}" \
  gdb -batch -x "${GDB_SCRIPT_PATH}" --args "${executable_and_args[@]}" 