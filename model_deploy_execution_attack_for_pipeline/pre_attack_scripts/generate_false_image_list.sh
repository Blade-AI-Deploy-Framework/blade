#!/bin/bash

# ==============================================================================
# Script to generate a list of image files that a model classifies as "false".
# It automatically determines the required model assets based on the executable's name.
#
# Usage:
# ./generate_false_image_list.sh <path_to_executable>
#
# Example:
# ./pre_attack_scripts/generate_false_image_list.sh resources/execution_files/emotion_ferplus_mnn
#
# Author: Gemini
# ==============================================================================

# --- Configuration ---
# Directory containing the images to test.
# IMPORTANT: Update this path to your image dataset.
IMAGE_DIR="/img_align_celeba"
# Directory where model files are stored.
MODEL_DIR="resources/models"
# Directory to save the list of false images.
OUTPUT_DIR="resources/false_image_list"


# --- Pre-run Checks & Setup ---
# Check if an executable was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_executable>"
    exit 1
fi

EXECUTABLE=$1
if [ ! -f "$EXECUTABLE" ]; then
    echo "Error: Executable '$EXECUTABLE' not found."
    exit 1
fi

# Check if the image directory exists
if [ ! -d "$IMAGE_DIR" ]; then
    echo "Error: Image directory '$IMAGE_DIR' not found."
    echo "Please check the IMAGE_DIR path in this script."
    exit 1
fi

# Check if the model directory exists
if [ ! -d "$MODEL_DIR" ]; then
    echo "Error: Model directory '$MODEL_DIR' not found."
    exit 1
fi

# Create output directory if it doesn't exist
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Info: Output directory '$OUTPUT_DIR' not found. Creating it."
    mkdir -p "$OUTPUT_DIR"
fi

# --- Environment Setup for Shared Libraries ---
# Add third-party library paths to LD_LIBRARY_PATH to ensure executables can find them.
# This assumes the script is run from the root of the `model_deploy_execution_attack` directory.
export LD_LIBRARY_PATH=third_party/mnn/lib:third_party/ncnn/lib:third_party/onnxruntime/lib:$LD_LIBRARY_PATH


# --- Dynamic Configuration ---
# Extract the base name of the executable to create a unique output file name.
EXECUTABLE_NAME=$(basename "$EXECUTABLE")
# Output file for logging the paths of "false" images, named after the model.
FALSE_LIST_FILE="$OUTPUT_DIR/${EXECUTABLE_NAME}_false_list.txt"


# --- 1. Parse Executable Name to find model and engine ---
exe_name=$(basename "$EXECUTABLE")
model_base=""
engine=""

if [[ $exe_name == *"_tflite"* ]]; then
    engine="tflite"
    model_base=${exe_name%_tflite}
elif [[ $exe_name == *"_onnxruntime"* ]]; then
    engine="onnxruntime"
    model_base=${exe_name%_onnxruntime}
elif [[ $exe_name == *"_ncnn"* ]]; then
    engine="ncnn"
    model_base=${exe_name%_ncnn}
elif [[ $exe_name == *"_mnn"* ]]; then
    engine="mnn"
    model_base=${exe_name%_mnn}
else
    echo "Error: Could not determine inference engine for '$exe_name'."
    echo "The executable name must end in _tflite, _onnxruntime, _ncnn, or _mnn."
    exit 1
fi

# --- 2. Map to Asset Files ---
model_asset_name=""
case $model_base in
    "age_googlenet") model_asset_name="age_googlenet" ;;
    "emotion_ferplus") model_asset_name="emotion_ferplus" ;;
    "fsanet_headpose") : ;; # Special handling below
    "gender_googlenet") model_asset_name="gender_googlenet" ;;
    "pfld_landmarks") model_asset_name="pfld_landmarks" ;;
    "ssrnet_age") model_asset_name="ssrnet_age" ;;
    "ultraface_detector") model_asset_name="ultraface_detector" ;;
    "yolov5_detector") model_asset_name="yolov5_detector" ;;
    "mnist") : ;; # MNIST does not require separate model files in this context
    *)
        echo "Warning: No asset mapping found for model base '$model_base'. Assuming model file has same base name."
        model_asset_name=$model_base
        ;;
esac

# --- 3. Construct Model Arguments ---
args=() # Initialize empty args array
# Handle the special case for fsanet_headpose
if [ "$model_base" = "fsanet_headpose" ]; then
    if [ "$engine" = "ncnn" ]; then
        var_param_path="$MODEL_DIR/fsanet-var.param"
        var_bin_path="$MODEL_DIR/fsanet-var.bin"
        conv_param_path="$MODEL_DIR/fsanet-1x1.param"
        conv_bin_path="$MODEL_DIR/fsanet-1x1.bin"
        if [ ! -f "$var_param_path" ] || [ ! -f "$var_bin_path" ] || \
           [ ! -f "$conv_param_path" ] || [ ! -f "$conv_bin_path" ]; then
            echo "Error: One or more NCNN models for 'fsanet_headpose' not found in $MODEL_DIR"
            exit 1
        fi
        args=("$var_param_path" "$var_bin_path" "$conv_param_path" "$conv_bin_path")
    else
        var_model_path=""
        conv_model_path=""
        case $engine in
            "tflite")
                var_model_path="$MODEL_DIR/fsanet-var_float16.tflite"
                conv_model_path="$MODEL_DIR/fsanet-1x1_float16.tflite"
                ;;
            "onnxruntime")
                var_model_path="$MODEL_DIR/fsanet-var.onnx"
                conv_model_path="$MODEL_DIR/fsanet-1x1.onnx"
                ;;
            "mnn")
                var_model_path="$MODEL_DIR/fsanet-var.mnn"
                conv_model_path="$MODEL_DIR/fsanet-1x1.mnn"
                ;;
        esac
        if [ ! -f "$var_model_path" ] || [ ! -f "$conv_model_path" ]; then
            echo "Error: One or more models for 'fsanet_headpose' not found in $MODEL_DIR"
            exit 1
        fi
        args=("$var_model_path" "$conv_model_path")
    fi
# Handle NCNN models which require param and bin paths
elif [ "$engine" = "ncnn" ]; then
    param_path="$MODEL_DIR/${model_asset_name}.param"
    bin_path="$MODEL_DIR/${model_asset_name}.bin"
    if [ ! -f "$param_path" ] || [ ! -f "$bin_path" ]; then
        echo "Error: NCNN model files not found for '$model_asset_name' in $MODEL_DIR"
        exit 1
    fi
    args=("$param_path" "$bin_path")
# For all other standard models
elif [ -n "$model_asset_name" ]; then
    model_path=""
    case $engine in
        "tflite")
            model_path="$MODEL_DIR/${model_asset_name}_float32.tflite"
            if [ ! -f "$model_path" ]; then
                model_path="$MODEL_DIR/${model_asset_name}.tflite"
            fi
            ;;
        "onnxruntime")
            model_path="$MODEL_DIR/${model_asset_name}.onnx"
            ;;
        "mnn")
            model_path="$MODEL_DIR/${model_asset_name}.mnn"
            ;;
    esac
    if [ ! -f "$model_path" ]; then
        echo "Error: Model file '$model_path' not found."
        exit 1
    fi
    args=("$model_path")
fi

# --- Main Logic ---
# Clear the previous list file to ensure a fresh start
> "$FALSE_LIST_FILE"

echo "Starting image classification to find 'false' images..."
echo "Model Executable: $EXECUTABLE"
echo "Model Arguments: ${args[@]}"
echo "Image Directory: $IMAGE_DIR"
echo "'False' images will be logged to: $FALSE_LIST_FILE"
echo "=================================================="

# Initialize counters
processed_count=0
false_count=0
# Optional: Set a limit for the number of 'false' images to find
FALSE_IMAGE_LIMIT=200

# Loop through all common image file types in the directory
while read -r image_path; do
    # Extract just the filename for cleaner logging
    image_name=$(basename "$image_path")

    # Run the model executable with the discovered arguments and the image path.
    # We redirect stderr to /dev/null to keep the output clean.
    output=$("$EXECUTABLE" "${args[@]}" "$image_path" 2>/dev/null)

    # Check if the output contains "false". Using `grep -q` is efficient.
    # The script assumes "false" indicates a negative classification.
    # Adjust this if your model uses different output (e.g., "Spoof face").
    if echo "$output" | grep -q "false"; then
        echo "[FALSE] -> $image_name"
        # Log the full path of the image to the output file
        echo "$image_path" >> "$FALSE_LIST_FILE"
        ((false_count++))
    fi

    ((processed_count++))
    # Provide progress feedback every 50 images
    if (( processed_count % 50 == 0 )); then
        echo "Processed $processed_count images..."
    fi

    # Check if we have found enough 'false' images and break if so
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