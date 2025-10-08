#!/bin/bash

# ==============================================================================
# Automated Batch Attack Script
#
# This script automates the process of running attacks on a model. It takes an
# executable file as input, automatically determines the required model,
# hooks configuration, and the list of "false" images to attack.
#
# Usage:
# ./scripts/run_automated_attack.sh <path_to_executable>
#
# Example:
# ./scripts/run_automated_attack.sh resources/execution_files/emotion_ferplus_mnn
# ==============================================================================

# --- Configuration ---
# Base directory of the project, determined relative to the script's location
BASE_DIR=$(realpath "$(dirname "$0")/..")

# Directory where model files are stored.
MODEL_DIR="$BASE_DIR/resources/models"
# Directory containing the list of false images.
FALSE_LIST_DIR="$BASE_DIR/resources/false_image_list"
# Directory for hook configurations
HOOK_CONFIG_DIR="$BASE_DIR/hook_config"
# Parent directory for all attack outputs
BASE_OUTPUT_PARENT_DIR="$BASE_DIR/outputs"

# Attacker script to use
ATTACK_SCRIPT="$BASE_DIR/src/attackers/nes_attack_targetless.py"

# --- Pre-run Checks & Setup ---
# Check if an executable was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_executable>"
    echo "Example: $0 resources/execution_files/emotion_ferplus_mnn"
    exit 1
fi

EXECUTABLE=$1
if [ ! -f "$EXECUTABLE" ]; then
    echo "Error: Executable '$EXECUTABLE' not found."
    exit 1
fi

EXECUTABLE_NAME=$(basename "$EXECUTABLE")

# --- Environment Setup for Shared Libraries ---
# Add third-party library paths to LD_LIBRARY_PATH to ensure executables can find them.
export LD_LIBRARY_PATH=$BASE_DIR/third_party/mnn/lib:$BASE_DIR/third_party/ncnn/lib:$BASE_DIR/third_party/onnxruntime/lib:$BASE_DIR/third_party/pplnn/lib:$BASE_DIR/third_party/tnn/lib:$LD_LIBRARY_PATH

# --- Python Virtual Environment Activation ---
# The user-specified virtual environment path.
VENV_PATH="$BASE_DIR/scripts/.venv/bin/activate"
if [ -f "$VENV_PATH" ]; then
    echo "Activating Python virtual environment from: $VENV_PATH"
    source "$VENV_PATH"
else
    echo "Warning: Python virtual environment not found at '$VENV_PATH'."
    echo "Proceeding with the system's default Python interpreter."
fi

# --- Dynamic Configuration ---

# 1. Determine paths based on executable name
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

# 2. Parse Executable Name to find model file
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

# 3. Map to Asset Files
model_asset_name=""
case $model_base in
    "age_googlenet") model_asset_name="age_googlenet" ;;
    "emotion_ferplus") model_asset_name="emotion_ferplus" ;;
    "fsanet_headpose")
        # This model is special, it uses two model files.
        # We will handle it separately.
        model_asset_name="fsanet_headpose" 
        ;;
    "gender_googlenet") model_asset_name="gender_googlenet" ;;
    "pfld_landmarks") model_asset_name="pfld_landmarks" ;;
    "ssrnet_age") model_asset_name="ssrnet_age" ;;
    "ultraface_detector") model_asset_name="ultraface_detector" ;;
    "yolov5_detector") model_asset_name="yolov5_detector" ;;
    "mnist") model_asset_name="mnist" ;;
    *)
        echo "Warning: No asset mapping found for model base '$model_base'. Assuming model file has same base name."
        model_asset_name=$model_base
        ;;
esac

# 4. Construct Model Path(s)
MODEL_PATH=""
MODELS_PATHS="" # For multi-model cases like fsanet_headpose

if [ "$engine" = "ncnn" ]; then
    echo "Error: NCNN models (.param/.bin) are not supported by this attack script, as it expects a single model file."
    exit 1
fi

if [ "$model_asset_name" = "fsanet_headpose" ]; then
    # Special handling for fsanet_headpose which requires two models
    model1_base_path="$MODEL_DIR/fsanet-var"
    model2_base_path="$MODEL_DIR/fsanet-1x1"
    model1_path=""
    model2_path=""
    case $engine in
        "tflite")
            model1_path="${model1_base_path}_float32.tflite"
            [ ! -f "$model1_path" ] && model1_path="${model1_base_path}.tflite"
            model2_path="${model2_base_path}_float32.tflite"
            [ ! -f "$model2_path" ] && model2_path="${model2_base_path}.tflite"
            ;;
        "onnxruntime")
            model1_path="${model1_base_path}.onnx"
            model2_path="${model2_base_path}.onnx"
            ;;
        "mnn")
            model1_path="${model1_base_path}.mnn"
            model2_path="${model2_base_path}.mnn"
            ;;
    esac
    if [ -f "$model1_path" ] && [ -f "$model2_path" ]; then
        MODELS_PATHS="$model1_path,$model2_path"
        echo "Detected multi-model: fsanet_headpose"
    else
        echo "Error: Could not find model files for fsanet_headpose."
        [ ! -f "$model1_path" ] && echo "Missing: $model1_path"
        [ ! -f "$model2_path" ] && echo "Missing: $model2_path"
        exit 1
    fi
else
    # Standard single-model handling
    if [ -n "$model_asset_name" ]; then
        case $engine in
            "tflite")
                MODEL_PATH="$MODEL_DIR/${model_asset_name}_float32.tflite"
                if [ ! -f "$MODEL_PATH" ]; then
                    MODEL_PATH="$MODEL_DIR/${model_asset_name}.tflite"
                fi
                ;;
            "onnxruntime")
                MODEL_PATH="$MODEL_DIR/${model_asset_name}.onnx"
                ;;
            "mnn")
                MODEL_PATH="$MODEL_DIR/${model_asset_name}.mnn"
                ;;
        esac
    fi
fi

# Final check for model paths
if [ -z "$MODEL_PATH" ] && [ -z "$MODELS_PATHS" ]; then
    echo "Error: Model file could not be found for '$EXECUTABLE_NAME'."
    echo "Tried to find: '$MODEL_PATH'"
    exit 1
fi


# --- Main Loop ---
echo "Starting batch attack for: $EXECUTABLE_NAME"
if [ -n "$MODELS_PATHS" ]; then
    echo "Models: $MODELS_PATHS"
else
    echo "Model: $MODEL_PATH"
fi
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
    # Create a descriptive and unique directory name for the output
    # The target state is unknown without a golden image, so we use a generic name.
    specific_output_dir="$BASE_OUTPUT_DIR/${image_name_no_ext}_attacked"
    
    # Create the directory
    mkdir -p "$specific_output_dir"

    # --- Construct Python Command ---
    # Start with the base command and common arguments
    PYTHON_CMD=(
        python3 "$ATTACK_SCRIPT"
        --executable "$EXECUTABLE"
        --hooks "$HOOKS_FILE"
        --image "$image_path"
        --output-dir "$specific_output_dir"
        --iterations 100
        --learning-rate 2.0
        --l-inf-norm 16.0
        --lr-decay-rate 0.97
        --lr-decay-steps 50
        --population-size 200
        --sigma 0.6
        --workers 64
        --enable-stagnation-decay
        --stagnation-patience 20
        --enable-dynamic-focus
        --evaluation-window 10
        --boost-weight 12.0
        --non-target-weight 1
    )

    # Conditionally add model argument(s)
    if [ -n "$MODELS_PATHS" ]; then
        PYTHON_CMD+=(--models "$MODELS_PATHS")
    else
        PYTHON_CMD+=(--model "$MODEL_PATH")
    fi

    # --- Execute the Attack Command ---
    # Note: --golden-image is removed as per requirements.
    # The attack script's parameters might need tuning for different models.
    "${PYTHON_CMD[@]}"

    echo ""
    echo "Attack on $image_path finished."
    echo "Results saved in: $specific_output_dir"
    echo "===================================================="
    echo ""
done < "$SPOOF_FACES_LIST"

echo "All attack tasks completed." 