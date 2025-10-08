#!/bin/bash

# Set -e option to exit immediately if a command exits with a non-zero status.
set -e

# --- Global Configuration ---
# Define a unified Ghidra project name
GHIDRA_PROJECT_DIR="ghidra_projects"
SINGLE_GHIDRA_PROJECT_NAME="all_binaries_analysis"
SINGLE_GHIDRA_PROJECT_PATH="$GHIDRA_PROJECT_DIR/$SINGLE_GHIDRA_PROJECT_NAME.gpr"
SINGLE_GHIDRA_PROJECT_REP_PATH="$GHIDRA_PROJECT_DIR/$SINGLE_GHIDRA_PROJECT_NAME.rep"

# Define the directory for binary files
BIN_DIR="assets/merged_bin"
# Define the list of analyzer scripts
ANALYZERS=("mnn_analyzer.py" "tflite_analyzer.py" "onnxruntime_analyzer.py" "ncnn_analyzer.py")
# Define the core script for running the analysis
HEADLESS_RUNNER="run_headless_test.sh"

# --- Pre-flight Checks ---
# Check if the core runner script exists and is executable
if [ ! -x "$HEADLESS_RUNNER" ]; then
    echo "Error: $HEADLESS_RUNNER not found or not executable."
    exit 1
fi

# Check if all analyzer scripts exist
for analyzer in "${ANALYZERS[@]}"; do
    if [ ! -f "$analyzer" ]; then
        echo "Error: Analyzer script $analyzer not found."
        exit 1
    fi
done

# Check if the binary directory exists
if [ ! -d "$BIN_DIR" ]; then
    echo "Error: Directory $BIN_DIR not found."
    exit 1
fi

echo "--- Cleaning up old unified Ghidra project (if it exists) ---"
if [ -f "$SINGLE_GHIDRA_PROJECT_PATH" ]; then
    echo "Deleting old Ghidra project file: $SINGLE_GHIDRA_PROJECT_PATH"
    rm -f "$SINGLE_GHIDRA_PROJECT_PATH"
fi
if [ -d "$SINGLE_GHIDRA_PROJECT_REP_PATH" ]; then
    echo "Deleting old Ghidra project data directory: $SINGLE_GHIDRA_PROJECT_REP_PATH"
    rm -rf "$SINGLE_GHIDRA_PROJECT_REP_PATH"
fi
echo "Old project cleanup complete."
echo ""


echo "--- Starting Batch Analysis ---"

# Iterate over all files in the specified directory
for executable_path in "$BIN_DIR"/*; do
    # Make sure we are processing a file and it is executable
    if [ -f "$executable_path" ] && [ -x "$executable_path" ]; then
        
        filename=$(basename -- "$executable_path")

        # --- New: Exclude specific executables based on prefix ---
        case "$filename" in
            mnist*|yolov5*|ultraface*|pfld*)
                echo "Skipping: $filename (excluded by prefix rule)"
                continue
                ;;
        esac
        
        analyzer_script=""
        framework_name=""

        # --- New Filename Parsing Logic ---
        # Remove possible .bin suffix (though executables usually don't have one)
        filename_no_ext="${filename%.*}"
        # Split filename by underscore
        IFS='_' read -r -a parts <<< "$filename_no_ext"
        num_parts=${#parts[@]}

        # Check if filename has at least three parts (e.g., model_framework_category)
        if [ $num_parts -ge 3 ]; then
            # The third to last field is the framework
            framework_field="${parts[num_parts-3]}"
            # The second to last field is the category
            category="${parts[num_parts-2]}"
            # The last field is the item
            item="${parts[num_parts-1]}"

            case "$framework_field" in
                mnn)
                    analyzer_script="mnn_analyzer.py"; framework_name="MNN" ;;
                tflite)
                    analyzer_script="tflite_analyzer.py"; framework_name="TFLite" ;;
                onnxruntime)
                    analyzer_script="onnxruntime_analyzer.py"; framework_name="ONNX Runtime" ;;
                ncnn)
                    analyzer_script="ncnn_analyzer.py"; framework_name="NCNN" ;;
                tnn)
                    framework_name="TNN"; analyzer_script="" ;;
                *)
                    framework_name=""; analyzer_script="" ;;
            esac

            # If a matching analyzer script is found, run the analysis
            if [ -n "$analyzer_script" ]; then
                # --- Construct New Output Path ---
                output_dir="results/$category/$item"
                # Ensure the output directory exists
                mkdir -p "$output_dir"
                # Full path for the output json file
                output_json_path="$output_dir/${filename}_hook_config.json"
                
                echo ""
                echo "======================================================================"
                echo "Performing [$framework_name] analysis on [$filename]..."
                echo "  - Ghidra Project: $SINGLE_GHIDRA_PROJECT_NAME"
                echo "  - Output Path: $output_json_path"
                echo "======================================================================"
                
                # Execute the analysis command, passing the unified project name and the desired output path
                ./"$HEADLESS_RUNNER" "$analyzer_script" "$executable_path" "$SINGLE_GHIDRA_PROJECT_NAME" "$output_json_path"
                
                echo "--- Analysis of [$filename] complete ---"
            else
                if [ "$framework_name" == "TNN" ]; then
                    echo "Skipping: $filename (TNN analyzer not yet supported)"
                else
                    echo "Skipping: $filename (No corresponding analyzer found for framework in third to last field: '$framework_field')"
                fi
            fi
        else
            echo "Skipping: $filename (Filename does not match 'name_framework_category_item' format)"
        fi
    fi
done

echo ""
echo "======================================================================"
echo "All analysis tasks have been completed."
echo "======================================================================"
