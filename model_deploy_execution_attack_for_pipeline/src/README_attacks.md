# Guide to the Automated Attack Testing Framework

## Overview

This document explains how to use the `run_all_attacks.sh` script to automatically execute a series of different adversarial attacks on a target AI application. The script wraps calls to `src/main_attack.py` and provides preset hyperparameters for each attack algorithm, enabling "one-click testing".

## Prerequisites

- Ensure that Python 3 and the required dependencies are installed in your environment.
- Make sure all modules and files referenced by `src/main_attack.py` exist and their paths are correct.

## Quick Start

1.  **Configure the Script**: Open the `run_all_attacks.sh` file and **you must modify** the `--- User Configuration ---` section at the top.
2.  **Execute the Script**: Run the following command in your terminal:
    ```bash
    bash run_all_attacks.sh
    ```
3.  **View Results**: For each attack, the script will create a timestamped subdirectory in the `attack_results/` directory, containing the generated adversarial sample images and a detailed `.csv` log file.

## Detailed Configuration Instructions

At the top of the `run_all_attacks.sh` script, you need to configure the following variables:

### 1. Target Program

You must configure one of `TARGET_EXECUTABLE` or `RAW_ARGS_TEMPLATE`.

-   `TARGET_EXECUTABLE`: Set this variable if your target program accepts simple command-line arguments.
    ```bash
    # Example:
    TARGET_EXECUTABLE="/path/to/your/face_analysis_cli"
    RAW_ARGS_TEMPLATE="" 
    ```

-   `RAW_ARGS_TEMPLATE`: Use this template if the target program's command-line argument format is complex. The script will replace `{IMAGE_PATH}` and `{MODEL_PATHS}` with the actual paths.
    ```bash
    # Example:
    TARGET_EXECUTABLE=""
    RAW_ARGS_TEMPLATE="./face_analysis_cli {MODEL_PATHS} analyze {IMAGE_PATH} out.bin"
    ```

### 2. File Paths

-   `TARGET_IMAGE`: Specify the path to the initial image for the attack.
-   `HOOK_CONFIG`: Specify the path to the `JSON` configuration file containing hook addresses and branch instructions.
-   `MODEL_PATHS`: Specify the path(s) to the AI model file(s). If there are multiple models, separate them with a **comma**`,` and no spaces.

### 3. Common Attack Parameters

-   `BASE_OUTPUT_DIR`: The root directory for all attack results.
-   `ITERATIONS`: The maximum number of iterations for each attack.
-   `L_INF_NORM`: The L-infinity norm constraint for the perturbation, i.e., the maximum change in pixel values.
-   `LEARNING_RATE`: The initial learning rate for the attack algorithm (Note: the `square` attack does not use this parameter).

## Customizing Tests

### 1. Running Specific Attacks

If you only want to run a subset of the attack algorithms, you can modify the `ATTACK_TYPES` array in the script.

```bash
# Example: Run only nes and square attacks
ATTACK_TYPES=("nes" "square")
```

### 2. Adjusting Hyperparameters

The specific hyperparameters for each attack algorithm are defined in the `case` statement block within the script. You can directly modify these values to test different parameter combinations.

```bash
case $attack_type in
    nes)
        # Modify the values here to adjust parameters for the nes attack
        specific_args="--population-size 50 --sigma 0.1"
        ;;
    spsa)
        # Modify the values here to adjust parameters for the spsa attack
        specific_args="--spsa-grad-samples 32 --spsa-c 0.05 --use-signed-grad"
        ;;
    # ... other attacks ...
esac
```

## Output Results

After the script executes, you will see a structure similar to the following in the `attack_results` directory:

```
attack_results/
├── nes_attack_20231027-143000/
│   ├── best_attack_image_nes.png
│   ├── latest_attack_image_nes.png
│   ├── successful_attack_image_nes.png  (if attack is successful)
│   └── 20231027-143000_nes_....csv      (detailed log)
│
├── spsa_attack_20231027-143510/
│   ├── ...
│
└── ...
```

-   `best_attack_image_*.png`: The image found so far that results in the minimum loss function value.
-   `latest_attack_image_*.png`: The image generated in the last iteration.
-   `successful_attack_image_*.png`: The first image that successfully satisfies all hook conditions.
-   `.csv` file: Contains detailed data for each iteration, such as loss value, query count, learning rate, success status, etc., for later analysis.
