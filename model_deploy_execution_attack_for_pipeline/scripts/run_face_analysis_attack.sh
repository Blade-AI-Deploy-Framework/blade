#!/bin/bash

# ==============================================================================
# Automated Attack Script for face_analysis_cli
#
# This script is specifically tailored to run attacks on the face_analysis_cli
# executable. It uses the --raw-args-template feature to handle the
# unique command-line structure of this target.
#
# It automatically finds the correct hook configuration and list of
# "false" images to attack.
#
# Usage:
# ./scripts/run_face_analysis_attack.sh <path_to_model_dir>
#
# Example:
# ./scripts/run_face_analysis_attack.sh ../Pikachu
# ==============================================================================

# --- Configuration ---
# Base directory of the project, determined relative to the script's location
BASE_DIR=$(realpath "$(dirname "$0")/..")

# --- Target Specific Configuration ---
EXECUTABLE_PATH="$BASE_DIR/resources/execution_files/face_analysis_cli"
MODEL_PATH="$BASE_DIR/resources/models/Pikachu" # Model file path
# Use a placeholder for the feature file path, which will be set dynamically for each image.
RAW_ARGS_TEMPLATE_FORMAT="$EXECUTABLE_PATH {MODEL_PATHS} analyze {IMAGE_PATH} {FEATURE_PATH}"

# --- Common Configuration ---
# Directory containing the list of false images.
FALSE_LIST_DIR="$BASE_DIR/resources/false_image_list"
# Directory for hook configurations
HOOK_CONFIG_DIR="$BASE_DIR/hook_config"
# Parent directory for all attack outputs
BASE_OUTPUT_PARENT_DIR="$BASE_DIR/outputs"
# Attacker script to use
ATTACK_SCRIPT="$BASE_DIR/src/attackers/nes_attack_targetless.py"

# --- Pre-run Checks & Setup ---
if [ ! -f "$EXECUTABLE_PATH" ]; then
    echo "Error: Executable '$EXECUTABLE_PATH' not found."
    exit 1
fi

if [ ! -f "$MODEL_PATH" ]; then
    echo "Error: Model file '$MODEL_PATH' not found."
    exit 1
fi

EXECUTABLE_NAME=$(basename "$EXECUTABLE_PATH")

# --- Environment Setup for Shared Libraries ---
# Add third-party library paths to LD_LIBRARY_PATH to ensure executables can find them.
export LD_LIBRARY_PATH=$BASE_DIR/third_party/mnn/lib:$BASE_DIR/third_party/onnxruntime/lib:$BASE_DIR/third_party/InspireFace/lib:$LD_LIBRARY_PATH

# --- Dynamic Configuration ---
HOOKS_FILE="$HOOK_CONFIG_DIR/${EXECUTABLE_NAME}_hook_config.json"
SPOOF_FACES_LIST="$FALSE_LIST_DIR/${EXECUTABLE_NAME}_false_list.txt"
BASE_OUTPUT_DIR="$BASE_OUTPUT_PARENT_DIR/${EXECUTABLE_NAME}_attack_results"

# Check for required files
if [ ! -f "$HOOKS_FILE" ]; then
    echo "Error: Hooks file not found at '$HOOKS_FILE'"
    echo "Please ensure a hook configuration file named '${EXECUTABLE_NAME}_hook_config.json' exists in '$HOOK_CONFIG_DIR'."
    exit 1
fi

if [ ! -f "$SPOOF_FACES_LIST" ]; then
    echo "Error: False image list not found at '$SPOOF_FACES_LIST'"
    echo "Please run the 'generate_false_image_list.sh' script first for this executable."
    exit 1
fi

# --- Main Loop ---
echo "Starting batch attack for: $EXECUTABLE_NAME"
echo "Model Path: $MODEL_PATH"
echo "Hooks: $HOOKS_FILE"
echo "Image List: $SPOOF_FACES_LIST"
echo "Output will be saved to: $BASE_OUTPUT_DIR"
echo "----------------------------------------------------"

# Create the base output directory if it doesn't exist
mkdir -p "$BASE_OUTPUT_DIR"

# Read the image list file line by line
while IFS= read -r image_path || [[ -n "$image_path" ]]; do
    # Filter out empty lines
    if [ -z "$image_path" ]; then
        continue
    fi

    # Check if the source image file exists
    if [ ! -f "$image_path" ]; then
        echo "Warning: Source image not found, skipping: $image_path"
        continue
    fi

    echo "===================================================="
    echo "Starting attack on: $image_path"
    echo "===================================================="

    # --- Create a unique output directory for this run ---
    base_filename=$(basename "$image_path")
    image_name_no_ext="${base_filename%.*}"
    specific_output_dir="$BASE_OUTPUT_DIR/${image_name_no_ext}_attacked"
    
    # Create the directory
    mkdir -p "$specific_output_dir"

    # --- Pre-attack Step: Generate feature file from the original image ---
    FEATURE_FILE_PATH="$specific_output_dir/original_feature.bin"
    echo "Generating feature file for original image..."
    echo "Command: $EXECUTABLE_PATH $MODEL_PATH extract \"$image_path\" \"$FEATURE_FILE_PATH\""
    
    "$EXECUTABLE_PATH" "$MODEL_PATH" extract "$image_path" "$FEATURE_FILE_PATH"
    
    if [ ! -f "$FEATURE_FILE_PATH" ]; then
        echo "Error: Failed to generate feature file. Skipping attack for this image."
        continue
    fi
    echo "Feature file generated at: $FEATURE_FILE_PATH"
    echo "----------------------------------------------------"

    # --- Dynamically create the raw-args-template for this run ---
    CURRENT_RAW_ARGS_TEMPLATE="${RAW_ARGS_TEMPLATE_FORMAT/\{FEATURE_PATH\}/$FEATURE_FILE_PATH}"

    # --- Construct Python Command ---
    # Use the --raw-args-template for this specific executable
    PYTHON_CMD=(
        python3 "$ATTACK_SCRIPT"
        --hooks "$HOOKS_FILE"
        --image "$image_path"
        --model "$MODEL_PATH"
        --raw-args-template "$CURRENT_RAW_ARGS_TEMPLATE"
        --output-dir "$specific_output_dir"
        --iterations 400
        --learning-rate 1.5
        --l-inf-norm 20.0
        --lr-decay-rate 0.97
        --lr-decay-steps 50
        --population-size 200
        --sigma 0.6
        --workers 64
        --enable-stagnation-decay
        --stagnation-patience 20
        --enable-dynamic-focus
        --evaluation-window 5
        --boost-weight 6.0
        --non-target-weight 1
    )

    # --- Execute the Attack Command ---
    "${PYTHON_CMD[@]}"

    echo ""
    echo "Attack on $image_path finished."
    echo "Results saved in: $specific_output_dir"
    echo "===================================================="
    echo ""
done < "$SPOOF_FACES_LIST"

echo "All attack tasks completed." 