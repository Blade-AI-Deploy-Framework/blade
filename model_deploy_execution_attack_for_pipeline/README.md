# Model Deployment and Execution Attack Pipeline

This project is a gray-box adversarial attack toolset for deployed models, supporting various inference engines like MNN, TFLite, and ONNX Runtime. It automates the entire process from environment setup and target screening to executing complex attacks using automated scripts and advanced attack algorithms. At its core is a Natural Evolution Strategies (NES)-based attack algorithm, which implements an innovative "Dynamic Focus" strategy to intelligently allocate attack resources and efficiently generate adversarial examples.

## File Structure Overview

```
.
├── hook_config/                # Directory for GDB Hook configuration files
├── outputs/                    # Output directory for attack results
├── pre_attack_scripts/         # Scripts for pre-attack preparation
├── README.md                   # Project documentation
├── resources/                  # Stores models, executables, images, etc.
├── scripts/                    # Main workflow scripts
└── src/                        # Source code
    └── attackers/              # Implementation of attack algorithms
```

## Quick Start

### 1. Environment Setup

This project is recommended to run in an **Ubuntu 24.04** environment. First, install all dependencies:

```bash
bash scripts/install_dependencies.sh
```

Then, activate the Python virtual environment:

```bash
source .venv/bin/activate
```

### 2. Prepare the Attack Target List (Crucial Step)

Before launching an attack, it's necessary to screen for images that the model "misclassifies" to use as a starting point.

1.  **Modify Configuration**: Open `pre_attack_scripts/generate_false_image_list.sh` and set the `IMAGE_DIR` variable to the path of your image dataset.
2.  **Run the Script**: Execute the script to generate a list of "false" images.

    ```bash
    # Example: Generate a list for emotion_ferplus_mnn
    bash pre_attack_scripts/generate_false_image_list.sh resources/execution_files/emotion_ferplus_mnn
    ```
    The generated list will be located in `resources/false_image_list/`.

### 3. Run the Automated Attack

Once ready, run the main attack script. It will automatically match the model, Hook configuration, and target list.

```bash
# Example: Launch an attack on emotion_ferplus_mnn
bash scripts/run_automated_attack.sh resources/execution_files/emotion_ferplus_mnn
```

Attack logs and results will be saved in the `outputs/` directory.

## Core Attack Strategy: Dynamic Focus NES

The `nes_attack_targetless.py` script employs an event-driven optimization strategy that is more complex than standard NES, designed to efficiently tackle the problem of attacking complex models with multiple decision branches. The core process is as follows:

### 1. Gradient Estimation and Optimizer

- **Gradient Estimation (NES)**: Utilizes Natural Evolution Strategies to estimate an effective "gradient" direction without accessing the model's gradients. This is done by adding random perturbations to the input image and observing the change in loss.
- **Optimizer (Adam)**: Uses the Adam optimizer to update the adversarial example based on the estimated gradient. It combines the advantages of first-order momentum and second-order adaptive learning rates, making the update process more stable and efficient.

### 2. Dynamic Focus Strategy Flow

The core idea of this strategy is to "concentrate superior forces to destroy the enemy forces one by one." Instead of attacking all decision branches (Hook points) simultaneously, it uses a dynamic, cyclical mechanism to intelligently select the most critical target at any given time.

- **Phase 1: Scouting Mode**
  - **Objective**: Identify the most "vulnerable" decision branches or those where progress can be most easily made.
  - **Method**: In the initial phase, all unsatisfied Hook points are given a low base weight. The algorithm runs for a fixed "evaluation window" (e.g., 10 iterations) and records the loss history for each Hook point. By analyzing the rate of loss descent through linear regression, the algorithm can determine which Hook points are most sensitive to the current perturbations.

- **Phase 2: Focused Fire Mode**
  - **Objective**: Concentrate firepower on the high-progress targets identified during the "Scouting" phase.
  - **Method**: Once targets are identified, the algorithm enters "Focused Fire" mode. It significantly increases the weight of these target Hook points in the total loss function (`--boost-weight`) while lowering the weight of other non-target and already satisfied Hook points. This ensures that gradient updates are primarily dedicated to overcoming the current core objectives.

- **Phase 3: Target Retirement & Rotation**
  - **Objective**: Promptly "retire" a target once it has been overcome and reallocate resources to new targets.
  - **Method**: In "Focused Fire" mode, the algorithm continuously monitors whether a target Hook point has met its condition for several consecutive iterations (i.e., its loss is below a certain threshold). Once the "retirement" condition is met (`--satisfaction-patience`), the target is removed from the core attack list, and its weight is adjusted to a lower "maintenance" state. When all current focus targets are "retired," the system automatically switches back to **Phase 1: Scouting Mode** to find the next set of most promising targets.

This "Scout-Focus-Retire" cycle continues until the entire attack mission is successful or the maximum number of iterations is reached.

### 3. Adaptive Learning Rate

To complement the dynamic strategy, the learning rate is also adjusted adaptively. There are two triggers for learning rate decay:
1.  **Fixed-Step Decay**: The learning rate decays whenever the iteration count reaches a certain number of steps (`--lr-decay-steps`).
2.  **Stagnation Decay**: If the overall loss does not show significant improvement over a number of consecutive iterations (`--stagnation-patience`), a learning rate decay is forcibly triggered.

This comprehensive strategy makes the attack process more intelligent and efficient, enabling it to effectively handle complex real-world models.

## Advanced Configuration and Customization

### Custom Attack Parameters

You can adjust the attack parameters of `nes_attack_targetless.py` to suit different models by modifying the `scripts/run_automated_attack.sh` script. Key parameters include:
- `--iterations`, `--learning-rate`, `--l-inf-norm`, `--population-size`
- Dynamic Focus strategy parameters: `--enable-dynamic-focus`, `--boost-weight`, `--evaluation-window`, `--satisfaction-patience`

### GDB Hook Configuration

Gray-box attacks rely on JSON files in the `hook_config/` directory to define GDB breakpoints and loss functions. A typical configuration item looks like this:
```json
[
  {
    "address": "0x5555555a7b14",
    "original_branch_instruction": "b.gt",
    "attack_mode": "invert"
  }
]
```
- `address`: The memory address where the breakpoint should be set.
- `original_branch_instruction`: The original branch instruction at that address, used to construct the loss function.
- `attack_mode`: `satisfy` (to meet the condition) or `invert` (to reverse the condition).





