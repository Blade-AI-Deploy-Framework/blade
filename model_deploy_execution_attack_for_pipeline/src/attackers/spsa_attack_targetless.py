import numpy as np
import cv2
import subprocess
import re
import os
import signal
import sys
import argparse
import json
import uuid
from concurrent.futures import ProcessPoolExecutor
import shutil
import tempfile
import glob
import time
from scipy import stats
import shlex
from collections import deque

def write_multiple_files_to_host(files_data, dest_dir):
    for filename, data in files_data:
        path = os.path.join(dest_dir, filename)
        with open(path, 'wb') as f:
            f.write(data)

def remove_files_on_host_batch(file_pattern):
    try:
        for f in glob.glob(file_pattern):
            os.remove(f)
    except OSError as e:
        print(f"Warning: Error while trying to batch remove '{file_pattern}': {e}")

def get_executable_output(image_path_on_host, args):
    if args.raw_args_template:
        # Replace placeholders for models and image
        model_paths_str = ' '.join([os.path.abspath(p) for p in args.model_paths])
        command_template = args.raw_args_template.replace('{MODEL_PATHS}', model_paths_str)
        command_template = command_template.replace('{IMAGE_PATH}', os.path.abspath(image_path_on_host))
        
        command = shlex.split(command_template)
        command[0] = os.path.abspath(command[0])
    else:
        executable_on_host = args.executable
        # Use the processed list of model paths
        model_paths_on_host = [os.path.abspath(p) for p in args.model_paths]

        command = [
            os.path.abspath(executable_on_host),
            *model_paths_on_host,
            os.path.abspath(image_path_on_host)
        ]

    script_dir = os.path.dirname(__file__)
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    mnn_lib_path = os.path.join(project_root, 'third_party', 'mnn', 'lib')
    onnx_lib_path = os.path.join(project_root, 'third_party', 'onnxruntime', 'lib')
    inspire_lib_path = os.path.join(project_root, 'third_party', 'InspireFace', 'lib')
    
    env = os.environ.copy()
    existing_ld_path = env.get('LD_LIBRARY_PATH', '')
    env['LD_LIBRARY_PATH'] = f"{mnn_lib_path}:{onnx_lib_path}:{inspire_lib_path}:{existing_ld_path}"

    try:
        result = subprocess.run(
            command, 
            check=True, 
            capture_output=True, 
            text=True, 
            timeout=30,
            env=env
        )
        return result.stdout + "\n" + result.stderr
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        stderr = e.stderr if hasattr(e, 'stderr') else "Timeout or error during execution"
        return f"Error running host executable for '{image_path_on_host}': {stderr}"

def _run_executable_and_parse_hooks(image_path_on_host, args):
    script_path = os.path.join(os.path.dirname(__file__), "run_gdb_host.sh") 
    
    if args.raw_args_template:
        # Replace placeholders for models and image
        model_paths_str = ' '.join([os.path.abspath(p) for p in args.model_paths])
        command_template = args.raw_args_template.replace('{MODEL_PATHS}', model_paths_str)
        command_template = command_template.replace('{IMAGE_PATH}', os.path.abspath(image_path_on_host))
        
        executable_and_args = shlex.split(command_template)
        executable_and_args[0] = os.path.abspath(executable_and_args[0])
        
        command = [
            '/bin/bash',
            script_path,
            *executable_and_args,
            os.path.abspath(args.hooks)
        ]
    else:
        executable_on_host = args.executable
        # Use the processed list of model paths
        model_paths_on_host = [os.path.abspath(p) for p in args.model_paths]

        command = [
            '/bin/bash',
            script_path,
            os.path.abspath(executable_on_host),
            *model_paths_on_host,
            os.path.abspath(image_path_on_host),
            os.path.abspath(args.hooks)
        ]

    script_dir = os.path.dirname(__file__)
    project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
    mnn_lib_path = os.path.join(project_root, 'third_party', 'mnn', 'lib')
    onnx_lib_path = os.path.join(project_root, 'third_party', 'onnxruntime', 'lib')
    inspire_lib_path = os.path.join(project_root, 'third_party', 'InspireFace', 'lib')
    
    env = os.environ.copy()
    existing_ld_path = env.get('LD_LIBRARY_PATH', '')
    env['LD_LIBRARY_PATH'] = f"{mnn_lib_path}:{onnx_lib_path}:{inspire_lib_path}:{existing_ld_path}"

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60, env=env)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        stderr = e.stderr if hasattr(e, 'stderr') else "Timeout or error during execution"
        print(f"Error running host executable for '{image_path_on_host}': {stderr}")
        return False, {}, {}

    hooked_values = {}
    hooked_errors = {}
    is_successful = False
    full_output = result.stdout + "\n" + result.stderr
    output_lines = full_output.splitlines()

    for line in output_lines:
        if "true" in line and "HOOK_RESULT" not in line: is_successful = True
        if "HOOK_RESULT" in line:
            match = re.search(r'offset=(0x[0-9a-fA-F]+)\s+.*value=(.*)', line)
            if not match: continue
            
            offset, val_str = match.groups()
            val_str = val_str.strip()

            try:
                value = None
                if val_str.startswith('{'):
                    float_match = re.search(r'f\s*=\s*([-\d.e+]+)', val_str)
                    if float_match:
                        value = float(float_match.group(1))
                else:
                    value = float(val_str)
                
                if value is not None:
                    if offset not in hooked_values:
                        hooked_values[offset] = []
                    hooked_values[offset].append(value)
            except (ValueError, TypeError): pass
        elif "HOOK_ERROR" in line:
            match = re.search(r'offset=(0x[0-9a-fA-F]+)\s+register=([\w\d]+)\s+reason="(.*)"', line)
            if not match: continue

            offset, register, reason = match.groups()
            if offset not in hooked_errors:
                hooked_errors[offset] = []
            hooked_errors[offset].append(f"Failed to read register '{register}': {reason}")
                
    return is_successful, hooked_values, hooked_errors

def evaluate_mutation_on_host(task_args):
    image_path_on_host, hook_config, dynamic_weights, args = task_args
    
    _, hooks, _ = _run_executable_and_parse_hooks(image_path_on_host, args)
    
    loss, _ = calculate_targetless_loss(hooks, hook_config, dynamic_weights, args.satisfaction_threshold, missing_hook_penalty=args.missing_hook_penalty)
    return loss

def run_attack_iteration(image_content, args, workdir, image_name_on_host):
    image_path_on_host = os.path.join(workdir, image_name_on_host)

    with open(image_path_on_host, 'wb') as f:
        f.write(image_content)

    is_successful, hooked_values, hooked_errors = _run_executable_and_parse_hooks(image_path_on_host, args)

    os.remove(image_path_on_host)
    
    return is_successful, hooked_values, hooked_errors


def calculate_targetless_loss(current_hooks, hook_config, dynamic_weights, satisfaction_threshold, margin=0.01, missing_hook_penalty=10.0, verbose=False):
    if verbose:
        print("\n" + "="*50)
        print("--- Loss Function Analysis ---")
        print("="*50)

    if not isinstance(current_hooks, dict):
        if verbose:
            print("Warning: Hook values are not a valid dictionary. This may indicate a crash or an error during execution.")
            print(f"Applying penalty for {len(hook_config)} hooks.")
        return len(hook_config) * missing_hook_penalty if hook_config else float('inf'), {}

    if not current_hooks and verbose:
        print("Warning: No hook values were captured for the image. The executable may have failed to run correctly.")
        print("The loss will be based on penalties for all configured hooks.")

    total_loss = 0.0
    hook_diagnostics = {}
    
    for hook_info in hook_config:
        address = hook_info.get("address")
        branch_instruction = hook_info.get("original_branch_instruction")
        
        if not all([address, branch_instruction]):
            continue

        dynamic_weight = dynamic_weights.get(address, 1.0)

        if verbose:
            print(f"Hook at {address}:")
            print(f"  - Branch Condition: '{branch_instruction}'")
            print(f"  - Dynamic Weight: {dynamic_weight}")

        values = current_hooks.get(address)
        hook_loss_sum = 0.0

        # New, structured format for per-pair configuration
        if "pairs_to_process" in hook_info:
            pairs_config = hook_info["pairs_to_process"]
            if verbose: print(f"  - Using detailed 'pairs_to_process' config for {len(pairs_config)} pairs.")

            if values is None:
                hook_loss_sum = missing_hook_penalty * len(pairs_config)
                if verbose: print(f"  - Hook Values: Not found. Applying penalty for {len(pairs_config)} required pair(s).")
            else:
                for pair_cfg in pairs_config:
                    pair_index = pair_cfg["pair_index"]
                    attack_mode = pair_cfg.get("attack_mode", "satisfy") # Default per-pair
                    hook_loss_sum += _calculate_loss_for_one_pair(values, pair_index, attack_mode, branch_instruction, margin, missing_hook_penalty, verbose, address)

        # Backward compatibility for flat value_pairs array
        else:
            pair_indices_to_process = hook_info.get("value_pairs", [1])
            attack_mode = hook_info.get("attack_mode", "satisfy")
            if verbose: 
                print(f"  - Using fallback 'value_pairs' config for indices: {pair_indices_to_process}")
                print(f"  - Shared Attack Mode: {attack_mode.upper()}")

            if values is None:
                hook_loss_sum = missing_hook_penalty * len(pair_indices_to_process)
                if verbose: print(f"  - Hook Values: Not found. Applying penalty for {len(pair_indices_to_process)} required pair(s).")
            else:
                for pair_index in pair_indices_to_process:
                    hook_loss_sum += _calculate_loss_for_one_pair(values, pair_index, attack_mode, branch_instruction, margin, missing_hook_penalty, verbose, address)

        loss_contribution = hook_loss_sum * dynamic_weight
        if verbose:
            print(f"  - Total Hook Loss (Sum of all pairs): {hook_loss_sum:.6f}")
            print(f"  - Weighted Loss Contribution: {loss_contribution:.6f}")
            print("-" * 25)

        total_loss += loss_contribution

        is_satisfied = hook_loss_sum < satisfaction_threshold
        hook_diagnostics[address] = {
            "individual_loss": hook_loss_sum,
            "is_satisfied": is_satisfied
        }

    if verbose:
        print(f"\nTotal Loss (Sum): {total_loss:.6f}")
        print("="*50)

    return total_loss, hook_diagnostics

def _calculate_loss_for_one_pair(values, pair_index, attack_mode, branch_instruction, margin, missing_hook_penalty, verbose, address):
    idx1 = (pair_index - 1) * 2
    idx2 = idx1 + 1
    
    pair_loss = 0.0
    formula = "N/A"

    if len(values) > idx2:
        v1, v2 = values[idx1], values[idx2]
        
        if verbose:
            print(f"  - Pair #{pair_index} (Mode: {attack_mode.upper()}) Values (v1, v2): ({v1:.4f}, {v2:.4f})")

        if attack_mode == 'invert':
            # Invert `v1 > v2` or `v1 >= v2` => Goal: `v1 <= v2` or `v1 < v2`. Penalize `v1 > v2`.
            if branch_instruction in ["b.gt", "b.hi", "b.ge", "b.hs", "b.cs", "b.pl"]:
                pair_loss = np.maximum(0, (v1 - v2) + margin)
                if verbose: formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})"
            # Invert `v1 < v2` or `v1 <= v2` => Goal: `v1 >= v2` or `v1 > v2`. Penalize `v1 < v2`.
            elif branch_instruction in ["b.lt", "b.lo", "b.cc", "b.mi", "b.le", "b.ls"]:
                pair_loss = np.maximum(0, (v2 - v1) + margin)
                if verbose: formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})"
            elif branch_instruction == "b.eq":
                # Goal: v1 != v2. Encourage |v1-v2| to be large.
                pair_loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
                if verbose: formula = f"max(0, {margin} - abs({v1:.4f} - {v2:.4f}))^2"
            elif branch_instruction == "b.ne":
                # Goal: v1 == v2. Encourage |v1-v2| to be small.
                pair_loss = (v1 - v2) ** 2
                if verbose: formula = f"({v1:.4f} - {v2:.4f})^2"
            else:
                if verbose: print(f"Warning: Unsupported branch instruction '{branch_instruction}' for pair #{pair_index} at {address}. Skipping.")
                return 0.0
        else:  # attack_mode == 'satisfy'
            # Satisfy `v1 > v2` or `v1 >= v2`. Penalize `v1 <= v2`.
            if branch_instruction in ["b.gt", "b.hi", "b.ge", "b.hs", "b.cs", "b.pl"]:
                pair_loss = np.maximum(0, (v2 - v1) + margin)
                if verbose: formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})"
            # Satisfy `v1 < v2` or `v1 <= v2`. Penalize `v1 >= v2`.
            elif branch_instruction in ["b.lt", "b.lo", "b.cc", "b.mi", "b.le", "b.ls"]:
                pair_loss = np.maximum(0, (v1 - v2) + margin)
                if verbose: formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})"
            elif branch_instruction == "b.eq":
                # Goal: v1 == v2.
                pair_loss = (v1 - v2) ** 2
                if verbose: formula = f"({v1:.4f} - {v2:.4f})^2"
            elif branch_instruction == "b.ne":
                # Goal: v1 != v2.
                pair_loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
                if verbose: formula = f"max(0, {margin} - abs({v1:.4f} - {v2:.4f}))^2"
            else:
                if verbose: print(f"Warning: Unsupported branch instruction '{branch_instruction}' for pair #{pair_index} at {address}. Skipping.")
                return 0.0 # Return 0 loss for this pair
    else:
        pair_loss = missing_hook_penalty
        if verbose:
            print(f"  - Pair #{pair_index}: Not found in captured values ({len(values)} total). Applying penalty.")
    
    if verbose and formula != "N/A":
        print(f"    - Formula: {formula}")
        print(f"    - Pair Loss: {pair_loss:.6f}")
        
    return pair_loss


def estimate_gradient_spsa(image, args, hook_config, workdir, dynamic_weights, current_c):
    run_id = uuid.uuid4().hex[:12]
    image_shape = image.shape
    num_samples = args.spsa_grad_samples
    
    # Determine perturbation shape based on attack mode
    if args.attack_y_channel_only:
        pert_shape = (image_shape[0], image_shape[1]) # H, W
        resize_downsampled_shape = (args.resize_dim, args.resize_dim) if args.resize_dim > 0 else None
    else:
        pert_shape = image_shape # H, W, C
        resize_downsampled_shape = (args.resize_dim, args.resize_dim, image_shape[2]) if args.resize_dim > 0 else None

    # Generate all perturbation vectors (deltas)
    deltas = []
    for _ in range(num_samples):
        if args.resize_dim and args.resize_dim > 0:
            delta_low_dim = np.random.choice([-1, 1], size=resize_downsampled_shape).astype(np.float32)
            delta = cv2.resize(delta_low_dim, (image_shape[1], image_shape[0]), interpolation=cv2.INTER_NEAREST)
        else:
            delta = np.random.choice([-1, 1], size=pert_shape).astype(np.float32)
        
        if delta.ndim == 2:
            delta = np.expand_dims(delta, axis=-1)
        deltas.append(delta)

    mutations_data_for_writing = []
    tasks = []

    # Create all mutated images and tasks for evaluation
    for i, delta in enumerate(deltas):
        if args.attack_y_channel_only:
            yuv_image = cv2.cvtColor(image.astype(np.uint8), cv2.COLOR_RGB2YUV).astype(np.float32)
            y_channel = yuv_image[:, :, 0]
            delta_squeezed = np.squeeze(delta, axis=-1)
            
            y_pos, y_neg = y_channel + current_c * delta_squeezed, y_channel - current_c * delta_squeezed
            
            yuv_pos = yuv_image.copy(); yuv_pos[:, :, 0] = y_pos
            mutant_pos = cv2.cvtColor(np.clip(yuv_pos, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB)

            yuv_neg = yuv_image.copy(); yuv_neg[:, :, 0] = y_neg
            mutant_neg = cv2.cvtColor(np.clip(yuv_neg, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB)
        else:
            mutant_pos = np.clip(image + current_c * delta, 0, 255)
            mutant_neg = np.clip(image - current_c * delta, 0, 255)

        _, encoded_pos = cv2.imencode(".png", cv2.cvtColor(mutant_pos.astype(np.uint8), cv2.COLOR_RGB2BGR))
        _, encoded_neg = cv2.imencode(".png", cv2.cvtColor(mutant_neg.astype(np.uint8), cv2.COLOR_RGB2BGR))
        
        fname_pos = f"temp_spsa_{run_id}_{i}_pos.png"
        fname_neg = f"temp_spsa_{run_id}_{i}_neg.png"
        
        mutations_data_for_writing.extend([(fname_pos, encoded_pos.tobytes()), (fname_neg, encoded_neg.tobytes())])
        
        path_pos = os.path.join(workdir, fname_pos)
        path_neg = os.path.join(workdir, fname_neg)
        tasks.extend([(path_pos, hook_config, dynamic_weights, args), (path_neg, hook_config, dynamic_weights, args)])

    try:
        total_mutations = len(mutations_data_for_writing)
        print(f"--- Writing {total_mutations} images for SPSA gradient estimation ---")
        write_multiple_files_to_host(mutations_data_for_writing, workdir)

        print(f"--- Evaluating {total_mutations} mutations with {args.workers} workers ---")
        losses = np.zeros(total_mutations)
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            results = executor.map(evaluate_mutation_on_host, tasks)
            for i, loss in enumerate(results):
                losses[i] = loss
        print("\nEvaluation complete.")

    finally:
        print("--- Batch removing temporary images from host ---")
        cleanup_pattern = os.path.join(workdir, f"temp_spsa_{run_id}_*.png")
        remove_files_on_host_batch(cleanup_pattern)

    # Calculate gradient
    if args.attack_y_channel_only:
        grad_shape = (image_shape[0], image_shape[1], 1)
        total_grads = np.zeros(grad_shape, dtype=np.float32)
    else:
        total_grads = np.zeros_like(image, dtype=np.float32)
        
    for i in range(num_samples):
        loss_pos, loss_neg = losses[2 * i], losses[2 * i + 1]
        if not (np.isinf(loss_pos) or np.isinf(loss_neg)):
            grad_sample = deltas[i] * ((loss_pos - loss_neg) / (2 * current_c + 1e-10))
            total_grads += grad_sample

    return total_grads / num_samples


def main(args):
    detailed_log_file = None
    attack_image = None
    best_loss_so_far = float('inf')
    best_image_path = None
    total_queries = 0
    start_time = time.time()

    try:
        os.setpgrp()
    except OSError:
        pass

    def sigint_handler(signum, frame):
        print("\nCtrl+C detected. Forcefully terminating all processes.")
        os.killpg(os.getpgrp(), signal.SIGKILL)

    signal.signal(signal.SIGINT, sigint_handler)

    # Process model paths from either --model or --models
    if args.models:
        args.model_paths = [p.strip() for p in args.models.split(',')]
    elif args.model:
        args.model_paths = args.model
    else:
        if args.raw_args_template and '{MODEL_PATHS}' in args.raw_args_template:
            raise ValueError("Raw args template contains '{MODEL_PATHS}' but no models were provided via --model or --models.")
        if not args.raw_args_template:
            raise ValueError("No model files provided. Use --model, --models, or --raw-args-template.")
        args.model_paths = []

    temp_dir_base = "/dev/shm" if os.path.exists("/dev/shm") else None
    workdir = tempfile.mkdtemp(prefix="spsa_host_attack_", dir=temp_dir_base)
    if temp_dir_base:
        print(f"--- Optimization: Using in-memory temp directory: {workdir} ---")
    
    try:
        os.makedirs(args.output_dir, exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        script_name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
        params_to_exclude = {'executable', 'image', 'hooks', 'model', 'models', 'start_adversarial', 'output_dir', 'workers'}
        args_dict = vars(args)
        param_str = "_".join([f"{key}-{val}" for key, val in sorted(args_dict.items()) if key not in params_to_exclude and val is not None and val is not False])
        param_str = re.sub(r'[^a-zA-Z0-9_\-.]', '_', param_str)
        log_filename = f"{timestamp}_{script_name}_{param_str[:100]}.csv"
        detailed_log_path = os.path.join(args.output_dir, log_filename)
        
        detailed_log_file = open(detailed_log_path, 'w')
        
        params_json = json.dumps(vars(args), indent=4, default=str)
        detailed_log_file.write("# --- Attack Parameters ---\n")
        for line in params_json.splitlines():
            detailed_log_file.write(f"# {line}\n")
        detailed_log_file.write("# -----------------------\n\n")

        log_header = [
            "iteration", "total_queries", "loss", "best_loss", "lr",
            "is_successful_iter", "num_satisfied_hooks", "total_hooks",
            "attack_mode", "focus_targets", "hook_details",
            "iter_time_s", "total_time_s"
        ]
        detailed_log_file.write(",".join(map(str, log_header)) + "\n")
        print(f"--- Detailed metrics will be logged to: {detailed_log_path} ---")

        stagnation_patience_counter = 0
        iteration_of_last_decay = 0
        total_decay_count = 0
        best_loss_for_stagnation = float('inf')
        if args.enable_stagnation_decay:
            print("--- Stagnation-resetting decay enabled ---")


        print("--- Preparing environment: Verifying local paths ---")
        if args.raw_args_template:
            executable_path = shlex.split(args.raw_args_template)[0]
            static_files = [executable_path, args.hooks] + args.model_paths
            if not os.path.isabs(executable_path):
                 print(f"--- Warning: Executable path '{executable_path}' in raw template is not absolute. Assuming it's in PATH or relative to CWD. ---")
        else:
            static_files = [args.executable, args.hooks] + args.model_paths
        
        gdb_script_path = os.path.join(os.path.dirname(__file__), "gdb_script_host.py")
        static_files.append(gdb_script_path)
        
        for f in static_files:
            if not os.path.exists(f):
                raise FileNotFoundError(f"Required file not found: {f}")

        print("--- Loading hook configuration from JSON ---")
        with open(args.hooks, 'r') as f:
            hook_config = json.load(f)
        if not hook_config:
            raise ValueError("Hook configuration file is empty or invalid.")
        print(f"--- Loaded {len(hook_config)} hook configurations. ---")


        hooks_attack_state = {}
        attack_mode = "scouting" if args.enable_dynamic_focus else "static"
        current_focus_target = None
        scouting_cycle_counter = 0

        if args.enable_dynamic_focus:
            print("\n--- Dynamic Focus Strategy ENABLED ---")
            for hook_info in hook_config:
                address = hook_info.get("address")
                if not address: continue
                hooks_attack_state[address] = {
                    "original_weight": float(hook_info.get("weight", 1.0)),
                    "dynamic_weight": args.non_target_weight,
                    "loss_history": [],
                    "descent_rate": 0.0,
                    "consecutive_satisfaction_count": 0
                }
            print(f"Initial mode: Scouting. All hooks set to base weight: {args.non_target_weight}")
        else:
            print("\n--- Static Weight Strategy ENABLED ---")
            for hook_info in hook_config:
                address = hook_info.get("address")
                if not address: continue
                hooks_attack_state[address] = {
                    "dynamic_weight": float(hook_info.get("weight", 1.0))
                }
        

        original_image = cv2.imread(args.image, cv2.IMREAD_COLOR)
        if original_image is None:
            raise FileNotFoundError(f"Could not read original image: {args.image}")

        if original_image.ndim == 2:
            original_image = cv2.cvtColor(original_image, cv2.COLOR_GRAY2BGR)
        
        original_image = cv2.cvtColor(original_image, cv2.COLOR_BGR2RGB)


        print("\n--- Calculating initial loss for original image ---")
        is_success_encoding, encoded_original_image = cv2.imencode(".png", cv2.cvtColor(original_image.astype(np.uint8), cv2.COLOR_RGB2BGR))
        if not is_success_encoding:
            raise RuntimeError("Failed to encode original image for initial analysis.")
        
        dynamic_weights = {addr: state["dynamic_weight"] for addr, state in hooks_attack_state.items()}
        _, initial_hooks, _ = run_attack_iteration(encoded_original_image.tobytes(), args, workdir, "initial_image_check.png")
        total_queries += 1
        
        _, _ = calculate_targetless_loss(initial_hooks, hook_config, dynamic_weights, args.satisfaction_threshold, margin=args.margin, missing_hook_penalty=args.missing_hook_penalty, verbose=True)

        print("\n--- Starting Attack Loop ---")
        
        attack_image = original_image.copy().astype(np.float32)
        original_image_float = original_image.copy().astype(np.float32)

        if args.attack_y_channel_only:
            pert_shape = (attack_image.shape[0], attack_image.shape[1], 1)
            m = np.zeros(pert_shape, dtype=np.float32)
            v = np.zeros(pert_shape, dtype=np.float32)
        else:
            m = np.zeros_like(attack_image, dtype=np.float32)
            v = np.zeros_like(attack_image, dtype=np.float32)
            
        beta1, beta2, epsilon_adam = args.adam_beta1, args.adam_beta2, args.adam_epsilon
        adam_step_counter = 0
        
        grad_history = None
        if args.grad_smoothing_samples > 1:
            grad_history = deque(maxlen=args.grad_smoothing_samples)
            print(f"--- Gradient smoothing enabled over {args.grad_smoothing_samples} samples ---")

        for i in range(args.iterations):
            iter_start_time = time.time()
            print(f"--- Iteration {i+1}/{args.iterations} (Total Queries: {total_queries}) ---")
            
            decay_reason = None
            if args.enable_stagnation_decay:
                if (i - iteration_of_last_decay) >= args.lr_decay_steps:
                    decay_reason = f"SCHEDULED ({args.lr_decay_steps} steps passed)"
                elif stagnation_patience_counter >= args.stagnation_patience:
                    decay_reason = f"STAGNATION ({args.stagnation_patience} stagnant iterations)"

                if decay_reason:
                    total_decay_count += 1
                    iteration_of_last_decay = i
                    stagnation_patience_counter = 0
                    
            current_lr = args.learning_rate * (args.lr_decay_rate ** total_decay_count)
            current_c = args.spsa_c / ((i + args.spsa_A) ** args.spsa_c_gamma)

            if decay_reason:
                 print(f"New LR: {current_lr:.6f}")

            dynamic_weights = {addr: state["dynamic_weight"] for addr, state in hooks_attack_state.items()}
            grad_raw = estimate_gradient_spsa(attack_image, args, hook_config, workdir, dynamic_weights, current_c)
            total_queries += 2 * args.spsa_grad_samples
            
            grad = grad_raw
            if grad_history is not None:
                grad_history.append(grad_raw)
                grad = np.mean(list(grad_history), axis=0)

            if args.use_signed_grad:
                grad = np.sign(grad)
            elif args.use_gradient_normalization:
                grad_norm = np.linalg.norm(grad)
                if grad_norm > 1e-8: grad = grad / grad_norm
            
            adam_step_counter += 1
            t = adam_step_counter
            m = beta1 * m + (1 - beta1) * grad
            v = beta2 * v + (1 - beta2) * (grad ** 2)
            m_hat = m / (1 - beta1 ** t)
            v_hat = v / (1 - beta2 ** t)
            update_step = current_lr * m_hat / (np.sqrt(v_hat + epsilon_adam))
            
            if args.attack_y_channel_only:
                attack_image_yuv = cv2.cvtColor(attack_image.astype(np.uint8), cv2.COLOR_RGB2YUV).astype(np.float32)
                attack_image_yuv[:, :, 0] -= np.squeeze(update_step, axis=-1)
                attack_image = cv2.cvtColor(np.clip(attack_image_yuv, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB).astype(np.float32)
            else:
                attack_image -= update_step

            perturbation = np.clip(attack_image - original_image_float, -args.l_inf_norm, args.l_inf_norm)
            attack_image = np.clip(original_image_float + perturbation, 0, 255)

            attack_image_uint8_rgb = attack_image.astype(np.uint8)
            attack_image_uint8_bgr = cv2.cvtColor(attack_image_uint8_rgb, cv2.COLOR_RGB2BGR)

            is_success_encoding, encoded_image = cv2.imencode(".png", attack_image_uint8_bgr)
            if not is_success_encoding:
                is_successful, current_hooks, loss, hook_diagnostics = False, {}, float('inf'), {}
            else:
                is_successful, current_hooks, hooked_errors = run_attack_iteration(encoded_image.tobytes(), args, workdir, "temp_attack_image.png")
                total_queries += 1
                loss, hook_diagnostics = calculate_targetless_loss(current_hooks, hook_config, dynamic_weights, args.satisfaction_threshold, margin=args.margin, missing_hook_penalty=args.missing_hook_penalty)
            
            iter_time = time.time() - iter_start_time
            total_time_so_far = time.time() - start_time
            print(f"Attack result: {'Success' if is_successful else 'Fail'}. Loss: {loss:.6f}. Iter Time: {iter_time:.2f}s. Total Time: {total_time_so_far:.2f}s")
            
            # --- Detailed Logging ---
            num_satisfied_hooks = sum(1 for d in hook_diagnostics.values() if d.get("is_satisfied", False))
            total_hooks = len(hook_config)
            
            hook_details_str = ""
            if is_successful or (i == args.iterations - 1):
                hook_details_for_log = {
                    addr: {"loss": round(float(diag.get("individual_loss", 0.0)), 6), "satisfied": bool(diag.get("is_satisfied", False))}
                    for addr, diag in hook_diagnostics.items()
                }
                hook_details_str = json.dumps(hook_details_for_log)

            targets_str = "N/A"
            if args.enable_dynamic_focus:
                if isinstance(current_focus_target, list):
                    targets_str = ";".join(current_focus_target) if current_focus_target else "None"
                elif current_focus_target:
                    targets_str = current_focus_target
                else:
                    targets_str = "None"

            log_data = [i + 1, total_queries, f"{loss:.6f}", f"{best_loss_so_far:.6f}", f"{current_lr:.6f}", is_successful, num_satisfied_hooks, total_hooks, attack_mode, f'"{targets_str}"', f'"{hook_details_str}"', f"{iter_time:.2f}", f"{total_time_so_far:.2f}"]
            detailed_log_file.write(",".join(map(str, log_data)) + "\n")
            detailed_log_file.flush()

            latest_image_path = os.path.join(args.output_dir, "latest_attack_image_spsa_host.png")
            cv2.imwrite(latest_image_path, attack_image_uint8_bgr)

            if loss < best_loss_so_far:
                best_loss_so_far = loss
                print(f"New best loss found: {loss:.6f}. Saving best image.")
                best_image_path = os.path.join(args.output_dir, "best_attack_image_spsa_host.png")
                cv2.imwrite(best_image_path, attack_image_uint8_bgr)

            if args.enable_stagnation_decay:
                if loss < best_loss_for_stagnation - args.min_loss_delta:
                    best_loss_for_stagnation = loss
                    stagnation_patience_counter = 0
                else: 
                    stagnation_patience_counter += 1
                print(f"Stagnation patience: {stagnation_patience_counter}/{args.stagnation_patience}")

            # Dynamic Focus Logic (omitted for brevity, assume it's the same as NES version)

            if is_successful:
                print("\nAttack successful according to GDB hooks!")
                successful_image_path = os.path.join(args.output_dir, "successful_attack_image_spsa_host.png")
                cv2.imwrite(successful_image_path, attack_image_uint8_bgr)
                print(f"Adversarial image saved to: {successful_image_path}")
                break

    except (FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"\nAn error occurred: {e}")
    finally:
        if detailed_log_file:
            detailed_log_file.close()
        if workdir and os.path.exists(workdir):
            shutil.rmtree(workdir)
            print(f"Temporary directory {workdir} cleaned up.")
        print("Cleanup finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A grey-box adversarial attack using SPSA (Targetless Host Version).")
    
    parser.add_argument("--executable", help="Local path to the target executable. Required if not using --raw-args-template.")
    parser.add_argument("--image", required=True, help="Local path to the initial image to be attacked.")
    parser.add_argument("--hooks", required=True, help="Local path to the JSON file defining hook points and loss conditions.")
    parser.add_argument("--model", nargs='+', help="One or more local paths to model files.")
    parser.add_argument("--models", type=str, help="A comma-separated string of model file paths.")
    parser.add_argument("--iterations", type=int, default=100, help="Maximum number of attack iterations.")
    parser.add_argument("--learning-rate", type=float, default=2.0, help="Initial learning rate for the attack.")
    parser.add_argument("--l-inf-norm", type=float, default=20.0, help="Maximum L-infinity norm for the perturbation.")
    parser.add_argument("--output-dir", type=str, default="attack_outputs_spsa_host", help="Directory to save output images and logs.")

    spsa_group = parser.add_argument_group("SPSA Settings")
    spsa_group.add_argument("--spsa-grad-samples", type=int, default=32, help="Number of gradient samples to average for SPSA.")
    spsa_group.add_argument("--spsa-c", type=float, default=0.1, help="SPSA parameter c for perturbation size.")
    spsa_group.add_argument("--spsa-c-gamma", type=float, default=0.101, help="SPSA parameter gamma for decaying c.")
    spsa_group.add_argument("--spsa-A", type=float, default=20.0, help="SPSA parameter A for stability.")

    stagnation_group = parser.add_argument_group("Stagnation-based Decay")
    stagnation_group.add_argument("--enable-stagnation-decay", action="store_true", help="Enable learning rate decay when loss stagnates.")
    stagnation_group.add_argument("--lr-decay-rate", type=float, default=0.97, help="Learning rate decay rate.")
    stagnation_group.add_argument("--lr-decay-steps", type=int, default=10, help="Decay learning rate every N steps.")
    stagnation_group.add_argument("--stagnation-patience", type=int, default=20, help="Iterations with no improvement before forcing a decay.")
    stagnation_group.add_argument("--min-loss-delta", type=float, default=0.001, help="Minimum change in loss to be considered an improvement for stagnation.")
    
    optimizer_group = parser.add_argument_group("Optimizer Settings")
    stabilization_group = optimizer_group.add_mutually_exclusive_group()
    stabilization_group.add_argument("--use-signed-grad", action="store_true", help="Use the sign of the gradient for the update step.")
    stabilization_group.add_argument("--use-gradient-normalization", action="store_true", help="Use L2 normalization on the gradient.")
    optimizer_group.add_argument("--grad-smoothing-samples", type=int, default=1, help="Number of recent gradients to average for a smoother update. Set to 1 to disable.")
    optimizer_group.add_argument("--adam-beta1", type=float, default=0.9, help="Adam optimizer beta1 parameter.")
    optimizer_group.add_argument("--adam-beta2", type=float, default=0.999, help="Adam optimizer beta2 parameter.")
    optimizer_group.add_argument("--adam-epsilon", type=float, default=1e-8, help="Adam optimizer epsilon parameter.")
    
    dynamic_focus_group = parser.add_argument_group("Dynamic Focus Strategy")
    # (Dynamic focus arguments can be copied from NES if needed)
    
    perturbation_group = parser.add_argument_group("Perturbation Settings")
    perturbation_group.add_argument("--resize-dim", type=int, default=0, help="Resize perturbation to this dimension before applying. 0 to disable.")
    perturbation_group.add_argument("--attack-y-channel-only", action="store_true", help="Perform the attack on the Y (luminance) channel only.")

    custom_command_group = parser.add_argument_group("Custom Command Execution")
    custom_command_group.add_argument("--raw-args-template", type=str, help="A raw command line template for executables with complex arguments.")
    
    parser.add_argument("--workers", type=int, default=os.cpu_count(), help="Number of parallel processes for evaluation.")
    parser.add_argument("--margin", type=float, default=0.05, help="A margin for the loss function.")
    parser.add_argument("--missing-hook-penalty", type=float, default=10.0, help="Penalty for missing hooks.")
    parser.add_argument("--satisfaction-threshold", type=float, default=0.01, help="Loss threshold for a hook to be satisfied.")
    
    cli_args = parser.parse_args()
    
    if not cli_args.raw_args_template and not cli_args.executable:
        parser.error("Either --executable or --raw-args-template must be provided.")

    main(cli_args)
