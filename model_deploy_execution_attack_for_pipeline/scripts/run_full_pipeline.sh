#!/bin/bash

# ==============================================================================
# Full Automated Attack Pipeline Script
#
# This script orchestrates the entire attack process for a predefined list of
# target executables. For each target, it first generates a list of "false"
# images and then runs the automated attack script against them.
#
# Usage:
# ./scripts/run_full_pipeline.sh
# ==============================================================================

# --- Configuration ---
# Set the base directory to the project root
BASE_DIR=$(realpath "$(dirname "$0")/..")

# Predefined list of target executables to run the full pipeline against.
# Add or remove executable names from this list as needed.
TARGETS=(
    "emotion_ferplus_mnn"
    "fsanet_headpose_mnn"
    "gender_googlenet_mnn"
    "ssrnet_age_mnn"
)

# Paths to the scripts to be executed
EXECUTABLE_DIR="$BASE_DIR/resources/execution_files"
GENERATE_LIST_SCRIPT="$BASE_DIR/pre_attack_scripts/generate_false_image_list.sh"
RUN_ATTACK_SCRIPT="$BASE_DIR/scripts/run_automated_attack.sh"
FALSE_LIST_DIR="$BASE_DIR/resources/false_image_list"

# --- Main Loop ---
echo "Starting the full automated attack pipeline for all targets..."
echo "======================================================================"
echo ""

for target in "${TARGETS[@]}"; do
    echo ">>> Processing Target: $target <<<"
    echo "----------------------------------------------------------------------"

    EXECUTABLE_PATH="$EXECUTABLE_DIR/$target"

    # --- Pre-run Check ---
    # Verify that the executable file for the current target exists.
    if [ ! -f "$EXECUTABLE_PATH" ]; then
        echo "[ERROR] Executable not found for '$target' at: $EXECUTABLE_PATH"
        echo "[INFO] Skipping all operations for this target."
        echo "----------------------------------------------------------------------"
        echo ""
        continue
    fi

    # --- Step 1: Generate False Image List ---
    echo "[Step 1/2] Checking for or generating false image list for '$target'..."
    
    FALSE_LIST_FILE="$FALSE_LIST_DIR/${target}_false_list.txt"
    if [ -f "$FALSE_LIST_FILE" ]; then
        echo "[INFO] False list '$FALSE_LIST_FILE' already exists. Skipping generation."
    else
        echo "[INFO] False list not found. Starting generation process..."
        "$GENERATE_LIST_SCRIPT" "$EXECUTABLE_PATH"

        # Check if the list generation script executed successfully.
        if [ $? -ne 0 ]; then
            echo "[ERROR] Failed to generate false image list for '$target'."
            echo "[INFO] Skipping attack phase for this target."
            echo "----------------------------------------------------------------------"
            echo ""
            continue
        else
            echo "[SUCCESS] Successfully generated false image list."
        fi
    fi

    echo ""

    # --- Step 2: Run Automated Attack ---
    echo "[Step 2/2] Starting automated attack for '$target'..."
    "$RUN_ATTACK_SCRIPT" "$EXECUTABLE_PATH"

    # Check if the attack script executed successfully.
    if [ $? -ne 0 ]; then
        echo "[ERROR] Automated attack script failed for '$target'."
    else
        echo "[SUCCESS] Automated attack finished for '$target'."
    fi

    echo "----------------------------------------------------------------------"
    echo ">>> Finished processing target: $target <<<"
    echo ""
    echo ""
done

echo "======================================================================"
echo "All automated attack pipelines have been completed."
echo "======================================================================" 