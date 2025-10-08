#!/bin/bash

# ==============================================================================
# Headless Ghidra Taint Analysis Test Script
#
# This script automates running a taint analysis script via Ghidra's headless
# analyzer. It uses a persistent project directory to cache analysis results,
# so only the first run on a binary is slow.
#
# Usage:
#   ./run_headless_test.sh <analysis_script.py> <path_to_binary> [ghidra_project_name] [full_output_path]
#
# Example (mnn_analyzer):
#   ./run_headless_test.sh mnn_analyzer.py assets/emotion_ferplus_mnn single_project results/cat/item/output.json
#
# Example (address_analyzer):
#   ./run_headless_test.sh address_analyzer.py assets/libInspireFace.so single_project 0x18c7e4
#
# ==============================================================================

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
# The script will first try to use the GHIDRA_HOME environment variable.
# If it's not set, it will fall back to the default path provided below.
# You can set the environment variable like this:
# export GHIDRA_HOME=/path/to/your/ghidra_11.x.x_PUBLIC

DEFAULT_GHIDRA_SUPPORT_PATH="/Applications/ghidra_11.0.3_PUBLIC/support"

if [ -n "$GHIDRA_HOME" ]; then
    GHIDRA_HEADLESS_PATH="$GHIDRA_HOME/support/analyzeHeadless"
    echo "INFO: Using Ghidra path from GHIDRA_HOME: $GHIDRA_HEADLESS_PATH"
else
    GHIDRA_HEADLESS_PATH="$DEFAULT_GHIDRA_SUPPORT_PATH/analyzeHeadless"
    echo "INFO: GHIDRA_HOME environment variable not set."
    echo "INFO: Using default Ghidra path: $GHIDRA_HEADLESS_PATH"
fi

# The directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# --- Script Arguments ---
if [ "$#" -lt 2 ]; then # At least the script and binary path are required, project name is optional
    echo "Usage: $0 <analysis_script.py> <path_to_binary> [ghidra_project_name] [full_output_path OR script_args...]"
    echo "Example (mnn_analyzer):     $0 mnn_analyzer.py assets/emotion_ferplus_mnn my_project results/output.json"
    echo "Example (address_analyzer): $0 address_analyzer.py assets/libInspireFace.so my_project 0x12345"
    echo "Example (library_analyzer): $0 library_analyzer.py assets/libfoo.so libfoo.so some_fallback_string"
    exit 1
fi

ANALYSIS_SCRIPT="$1"
TARGET_BINARY_PATH="$2"
# Extract the basename of the binary to use in output filenames
BINARY_BASENAME=$(basename "$TARGET_BINARY_PATH")

# --- Argument Parsing for Project Name and Output Path ---
GHIDRA_PROJECT_NAME="$BINARY_BASENAME" # Default project name
TARGET_OUTPUT_PATH=""                 # Default empty target output path

# Check for the 3rd argument (Project Name)
if [ -n "$3" ]; then
    # This logic assumes that if a 4th argument is present, the 3rd is the project name.
    # It also handles the old case where the 3rd arg might be a script argument (like an address).
    # A more robust solution might require flags, but this maintains compatibility.
    
    # If 4th arg exists, 3rd must be project name.
    if [ -n "$4" ]; then
        GHIDRA_PROJECT_NAME="$3"
        # Check if 4th argument is the output path (must contain "results/")
        if [[ "$4" == *results/* ]]; then
            TARGET_OUTPUT_PATH="$4"
            shift 4
        else
            # 4th argument is a script arg
            shift 3
        fi
    # If only 3rd arg exists, check if it's a project name or script arg
    elif ! [[ "$3" =~ ^0x[0-9a-fA-F]+$ ]]; then # Not an address
         GHIDRA_PROJECT_NAME="$3"
         shift 3
    else # It's a script arg
         shift 2
    fi
else
    shift 2 # Only script and binary were provided
fi
SCRIPT_ARGS_FOR_PYTHON=("$@")

# --- Persistent Project Setup ---
# A permanent directory to store Ghidra projects, avoiding re-analysis.
GHIDRA_PROJECTS_DIR="$SCRIPT_DIR/ghidra_projects"
mkdir -p "$GHIDRA_PROJECTS_DIR"

# The Ghidra project will be named after the binary.
# GHIDRA_PROJECT_NAME is now set from the 3rd argument or defaults to BINARY_BASENAME
GHIDRA_PROJECT_FULL_PATH="$GHIDRA_PROJECTS_DIR/$GHIDRA_PROJECT_NAME.gpr" # Ghidra project file path

# --- Output Directories and Files ---
LOG_DIR="$SCRIPT_DIR/logs"
RESULTS_DIR="$SCRIPT_DIR/results"
mkdir -p "$LOG_DIR"
mkdir -p "$RESULTS_DIR"

# Output files
LOG_FILE="$LOG_DIR/${BINARY_BASENAME}_headless_analysis.log"
# Default filename that will be passed via environment variable.
# This points to the generic, top-level results directory.
# Python scripts that respect the env var will write here.
JSON_OUTPUT_FILE_DEFAULT="$RESULTS_DIR/${BINARY_BASENAME}_taint_analysis_results.json"

# However, some scripts have hardcoded output names. We need to know which file
# to look for in the final verification step. This is the source file to be moved.
# This logic assumes the Python script ALWAYS writes to the top-level results dir.
HARCODED_PY_OUTPUT_FILE="$RESULTS_DIR/${BINARY_BASENAME}_hook_config.json"

# Determine the final, user-specified destination for the output file.
# If TARGET_OUTPUT_PATH was not passed as an argument, we determine a default.
if [ -n "$TARGET_OUTPUT_PATH" ]; then
    FINAL_OUTPUT_FILE="$TARGET_OUTPUT_PATH"
else
    # Fallback for manual runs: determine if it's a hook_config or taint_analysis result.
    if [[ "$ANALYSIS_SCRIPT" == "mnn_analyzer.py" || "$ANALYSIS_SCRIPT" == "library_analyzer.py" || "$ANALYSIS_SCRIPT" == "tflite_analyzer.py" || "$ANALYSIS_SCRIPT" == "onnxruntime_analyzer.py" || "$ANALYSIS_SCRIPT" == "ncnn_analyzer.py" ]]; then
        FINAL_OUTPUT_FILE="$HARCODED_PY_OUTPUT_FILE"
    else
        FINAL_OUTPUT_FILE="$JSON_OUTPUT_FILE_DEFAULT"
    fi
fi


# --- Pre-flight Checks ---
if [ ! -f "$GHIDRA_HEADLESS_PATH" ]; then
    echo "ERROR: Ghidra headless analyzer not found at '$GHIDRA_HEADLESS_PATH'"
    echo "Please update the GHIDRA_HEADLESS_PATH variable in this script."
    exit 1
fi

if [ ! -f "$TARGET_BINARY_PATH" ]; then
    echo "ERROR: Target binary not found at '$TARGET_BINARY_PATH'"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/$ANALYSIS_SCRIPT" ]; then
    echo "ERROR: Analysis script not found at '$SCRIPT_DIR/$ANALYSIS_SCRIPT'"
    exit 1
fi

# --- Main Execution ---
echo "Starting headless Ghidra taint analysis..."
echo "  - Ghidra Project Dir:  $GHIDRA_PROJECTS_DIR"
echo "  - Ghidra Project Name: $GHIDRA_PROJECT_NAME"
echo "  - Target Binary:       $TARGET_BINARY_PATH"
echo "  - Analysis Script:     $ANALYSIS_SCRIPT"

# --- Build arguments for the Ghidra post-script ---
POST_SCRIPT_ARGS=("$ANALYSIS_SCRIPT")
if [ ${#SCRIPT_ARGS_FOR_PYTHON[@]} -gt 0 ]; then
    # The expansion with [*] joins the arguments into a single string for logging.
    echo "  - Script Arguments:    ${SCRIPT_ARGS_FOR_PYTHON[*]}"
    POST_SCRIPT_ARGS+=("${SCRIPT_ARGS_FOR_PYTHON[@]}")
fi

echo "  - Log File:            $LOG_FILE"
echo "  - Final Output Path:   $FINAL_OUTPUT_FILE"

# Clean up previous analysis log and result files
echo "Cleaning up previous analysis logs and potential output files..."
rm -f "$LOG_FILE"
# Clean up all possible output locations to be safe
rm -f "$JSON_OUTPUT_FILE_DEFAULT"
rm -f "$HARCODED_PY_OUTPUT_FILE"
if [ -n "$TARGET_OUTPUT_PATH" ]; then
    rm -f "$TARGET_OUTPUT_PATH"
fi

# Export the environment variable for the Python script to know where to save the JSON output.
export TAINT_ANALYSIS_JSON_OUTPUT="$JSON_OUTPUT_FILE_DEFAULT"

# --- Run the headless analyzer ---
# MODIFICATION: The project is no longer deleted with each run.
# This allows multiple binaries to be imported into a single, shared project.
# The cleanup is now handled by the parent script (run_all_analyses.sh).

# echo "Performing Ghidra analysis..."
# The -process option will import the file if it's not already in the project.
# If it is already imported, it will open the project and proceed to run the script.
# This is more efficient than re-importing every time.
# However, for simplicity and to ensure the latest binary is used, we stick with -import.
# Ghidra's -import is idempotent; it will re-analyze if the file has changed or just
# open it if it's already pristine.
"$GHIDRA_HEADLESS_PATH" "$GHIDRA_PROJECTS_DIR" "$GHIDRA_PROJECT_NAME" \
    -import "$TARGET_BINARY_PATH" -overwrite \
    -scriptPath "$SCRIPT_DIR" \
    -postScript "${POST_SCRIPT_ARGS[@]}" \
    -log "$LOG_FILE"

echo "Ghidra analysis finished."

# --- Verification and File Move ---
# The python script ran. Now we need to find the output file it created
# and move it to the desired final destination if needed.

PY_GENERATED_FILE=""
# Check which of the possible default files was created by the script.
if [ -f "$HARCODED_PY_OUTPUT_FILE" ]; then
    PY_GENERATED_FILE="$HARCODED_PY_OUTPUT_FILE"
elif [ -f "$JSON_OUTPUT_FILE_DEFAULT" ]; then
    PY_GENERATED_FILE="$JSON_OUTPUT_FILE_DEFAULT"
fi

if [ -n "$PY_GENERATED_FILE" ]; then
    echo "✅ SUCCESS: Python script generated '$PY_GENERATED_FILE'"
    
    # Move the file to its final destination if it's different
    if [ "$PY_GENERATED_FILE" != "$FINAL_OUTPUT_FILE" ]; then
        echo "Moving output file to its final destination: $FINAL_OUTPUT_FILE"
        # Ensure the final destination directory exists
        mkdir -p "$(dirname "$FINAL_OUTPUT_FILE")"
        mv "$PY_GENERATED_FILE" "$FINAL_OUTPUT_FILE"
    fi
    
    # Final check to ensure the file is at its destination
    if [ -f "$FINAL_OUTPUT_FILE" ]; then
        echo "✅ SUCCESS: Taint analysis results saved to '$FINAL_OUTPUT_FILE'"
        echo "You can view the full Ghidra log at '$LOG_FILE'"
    else
        echo "❌ FAILURE: Failed to move file to '$FINAL_OUTPUT_FILE'"
        exit 1
    fi
else
    echo ""
    echo "❌ FAILURE: The analysis script did not create an output file in any expected location."
    echo "Please check the log file for errors: '$LOG_FILE'"
    exit 1
fi

# --- Clean up Python .py.class cache files ---
echo "Cleaning up Python .py.class cache files in $SCRIPT_DIR ..."
find "$SCRIPT_DIR" -name "*py.class" -type f -delete

exit 0 