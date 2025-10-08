#!/bin/bash
#
# This is an automated testing script to run all supported adversarial attack algorithms with a single command.
# Before running, please make sure to modify the "User Configuration" section below.
#
# --- User Configuration ---
# Please replace the placeholder paths here with your actual file paths.

# Target executable or raw command template
# Example 1: Using --executable
TARGET_EXECUTABLE="/path/to/your/face_analysis_cli"
RAW_ARGS_TEMPLATE="" # Leave this empty if using --executable

# Example 2: Using --raw-args-template
# TARGET_EXECUTABLE="" # Leave this empty if using --raw-args-template
# RAW_ARGS_TEMPLATE="./face_analysis_cli {MODEL_PATHS} analyze {IMAGE_PATH} out.bin"

# Other required file paths for the attack
TARGET_IMAGE="dataset/test1.jpg"
HOOK_CONFIG="hook_config/face_analysis_cli_hook_config.json"
MODEL_PATHS="resources/models/your_model.bin,resources/models/another_model.mnn" # Separate multiple models with a comma

# Common attack parameters
BASE_OUTPUT_DIR="attack_results" # Root directory for all attack results
ITERATIONS=1000 # Maximum number of iterations for each attack
L_INF_NORM=20.0 # L-infinity norm constraint
LEARNING_RATE=15.0 # Initial learning rate

# --- Core Script Logic ---

# Define the list of attack algorithms to test
ATTACK_TYPES=("nes" "spsa" "bandit" "square" "zosignsgd")

# Check whether to use --executable or --raw-args-template
if [[ -n "$TARGET_EXECUTABLE" ]]; then
    EXEC_ARGS="--executable $TARGET_EXECUTABLE"
elif [[ -n "$RAW_ARGS_TEMPLATE" ]]; then
    EXEC_ARGS="--raw-args-template \"$RAW_ARGS_TEMPLATE\""
else
    echo "Error: Please configure either TARGET_EXECUTABLE or RAW_ARGS_TEMPLATE in the script."
    exit 1
fi

echo "Starting automated attack tests..."
echo "========================================"

# Loop through and execute each attack
for attack_type in "${ATTACK_TYPES[@]}"; do
    
    ATTACK_OUTPUT_DIR="$BASE_OUTPUT_DIR/${attack_type}_attack_$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$ATTACK_OUTPUT_DIR"
    
    echo ""
    echo "--- Starting [${attack_type^^}] attack ---"
    echo "Results will be saved in: $ATTACK_OUTPUT_DIR"
    
    # Set specific hyperparameters for different attack types
    specific_args=""
    case $attack_type in
        nes)
            specific_args="--population-size 50 --sigma 0.1"
            ;;
        spsa)
            specific_args="--spsa-grad-samples 32 --spsa-c 0.05 --use-signed-grad"
            ;;
        bandit)
            specific_args="--fd-eta 0.1 --prior-exploration 0.1 --prior-size 32"
            ;;
        square)
            specific_args="--p-init 0.05"
            # The Square attack does not use a learning rate, but the parameter is kept for command consistency. It won't actually be used.
            ;;
        zosignsgd)
            specific_args="--num-queries 100 --fd-eta 0.1"
            ;;
    esac

    # Build and execute the full command
    COMMAND="python src/main_attack.py \
        --attack-type $attack_type \
        $EXEC_ARGS \
        --image $TARGET_IMAGE \
        --hooks $HOOK_CONFIG \
        --models $MODEL_PATHS \
        --output-dir $ATTACK_OUTPUT_DIR \
        --iterations $ITERATIONS \
        --l-inf-norm $L_INF_NORM \
        --learning-rate $LEARNING_RATE \
        $specific_args"

    echo "Executing command:"
    echo "$COMMAND"
    echo ""

    # Execute the command
    eval $COMMAND

    echo "--- [${attack_type^^}] attack finished ---"
    echo "========================================"
done

echo "All attack tests have been completed!"
