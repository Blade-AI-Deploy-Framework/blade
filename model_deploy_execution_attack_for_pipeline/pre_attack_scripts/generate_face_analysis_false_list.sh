#!/bin/bash

# ==============================================================================
# Script to generate a list of "false" images for face_analysis_cli.
#
# This script iterates through an image directory. For each image, it extracts
# its feature vector and then analyzes the image against its own feature.
# If the result is "false" (indicating a failed self-match), the image
# is added to a list, as it's a good starting point for an attack.
#
# Usage:
# ./pre_attack_scripts/generate_face_analysis_false_list.sh <path_to_model_dir>
#
# Example:
# ./pre_attack_scripts/generate_face_analysis_false_list.sh ./resources/models/Pikachu
# ==============================================================================

# --- Configuration ---
# Directory containing the images to test.
# IMPORTANT: Update this path to your image dataset.
IMAGE_DIR="/home/ckx/img_align_celeba"
# Directory to save the list of false images.
OUTPUT_DIR="resources/false_image_list"

# --- Pre-run Checks & Setup ---
# Base directory of the project, determined relative to the script's location
BASE_DIR=$(realpath "$(dirname "$0")/..")
EXECUTABLE_PATH="$BASE_DIR/resources/execution_files/face_analysis_cli"
MODEL_PATH="./resources/models/Pikachu"

if [ -z "$MODEL_PATH" ]; then
    echo "Usage: $0"
    exit 1
fi

if [ ! -f "$EXECUTABLE_PATH" ]; then
    echo "Error: Executable '$EXECUTABLE_PATH' not found."
    exit 1
fi

if [ ! -f "$MODEL_PATH" ]; then
    echo "Error: Model file '$MODEL_PATH' not found."
    exit 1
fi

if [ ! -d "$IMAGE_DIR" ]; then
    echo "Error: Image directory '$IMAGE_DIR' not found."
    echo "Please check the IMAGE_DIR path in this script."
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# --- Environment Setup for Shared Libraries ---
export LD_LIBRARY_PATH=$BASE_DIR/third_party/mnn/lib:$BASE_DIR/third_party/onnxruntime/lib:$BASE_DIR/third_party/InspireFace/lib:$LD_LIBRARY_PATH

# --- Dynamic Configuration ---
EXECUTABLE_NAME=$(basename "$EXECUTABLE_PATH")
FALSE_LIST_FILE="$OUTPUT_DIR/${EXECUTABLE_NAME}_false_list.txt"

# Create a temporary directory for feature files
TEMP_FEATURE_DIR=$(mktemp -d)
# Ensure the temporary directory is cleaned up on script exit
trap 'rm -rf -- "$TEMP_FEATURE_DIR"' EXIT

# --- Main Logic ---
> "$FALSE_LIST_FILE"

echo "Starting image analysis to find 'false' self-matches..."
echo "Executable: $EXECUTABLE_PATH"
echo "Model Path: $MODEL_PATH"
echo "Image Directory: $IMAGE_DIR"
echo "'False' images will be logged to: $FALSE_LIST_FILE"
echo "=================================================="

processed_count=0
false_count=0
FALSE_IMAGE_LIMIT=200

while read -r image_path; do
    image_name=$(basename "$image_path")
    temp_feature_file="$TEMP_FEATURE_DIR/temp_feature.bin"

    # 1. Extract the feature from the image
    "$EXECUTABLE_PATH" "$MODEL_PATH" extract "$image_path" "$temp_feature_file" >/dev/null 2>&1
    
    # Check if feature extraction was successful
    if [ ! -f "$temp_feature_file" ]; then
        echo "[SKIP] -> Feature extraction failed for $image_name"
        continue
    fi

    # 2. Analyze the image against its own feature
    output=$("$EXECUTABLE_PATH" "$MODEL_PATH" analyze "$image_path" "$temp_feature_file" 2>/dev/null)

    # 3. Check if the output contains "false"
    if echo "$output" | grep -q "false"; then
        echo "[FALSE] -> $image_name"
        echo "$image_path" >> "$FALSE_LIST_FILE"
        ((false_count++))
    fi

    ((processed_count++))
    if (( processed_count % 50 == 0 )); then
        echo "Processed $processed_count images..."
    fi

    if [ -n "$FALSE_IMAGE_LIMIT" ] && [ "$false_count" -ge "$FALSE_IMAGE_LIMIT" ]; then
        echo ""
        echo "Found $false_count 'false' images, which reaches the limit of $FALSE_IMAGE_LIMIT. Stopping."
        break
    fi
done < <(find "$IMAGE_DIR" -type f \( -iname \*.jpg -o -iname \*.jpeg -o -iname \*.png -o -iname \*.bmp \))

# --- Summary ---
echo "=================================================="
echo "Script finished."
echo "Total images processed: $processed_count"
echo "Total 'false' images found: $false_count"
echo "List of 'false' images has been saved to '$FALSE_LIST_FILE'."
echo "Temporary feature directory '$TEMP_FEATURE_DIR' will be cleaned up." 