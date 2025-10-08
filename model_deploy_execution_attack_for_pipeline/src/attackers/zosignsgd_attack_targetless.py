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


def estimate_gradient_zosignsgd(image, args, hook_config, workdir, dynamic_weights):
    run_id = uuid.uuid4().hex[:12]
    image_shape = image.shape
    q = args.num_queries
    fd_eta = args.fd_eta
    
    # First, get the loss of the original image
    _, encoded_original = cv2.imencode(".png", cv2.cvtColor(image.astype(np.uint8), cv2.COLOR_RGB2BGR))
    base_image_path = os.path.join(workdir, f"temp_zo_{run_id}_base.png")
    with open(base_image_path, 'wb') as f:
        f.write(encoded_original.tobytes())
    
    base_loss = evaluate_mutation_on_host((base_image_path, hook_config, dynamic_weights, args))
    os.remove(base_image_path)

    noise_vectors = [np.random.randn(*image_shape) for _ in range(q)]
    mutations_data_for_writing = []
    tasks = []

    for i, noise in enumerate(noise_vectors):
        mutant_pos = image + fd_eta * noise
        mutant_pos = np.clip(mutant_pos, 0, 255)

        _, encoded_pos = cv2.imencode(".png", cv2.cvtColor(mutant_pos.astype(np.uint8), cv2.COLOR_RGB2BGR))
        
        unique_id_pos = f"{run_id}_{i}_pos"
        fname_pos = f"temp_zo_{unique_id_pos}.png"
        
        mutations_data_for_writing.append((fname_pos, encoded_pos.tobytes()))
        path_pos = os.path.join(workdir, fname_pos)
        tasks.append((path_pos, hook_config, dynamic_weights, args))

    try:
        print(f"--- Writing {len(mutations_data_for_writing)} images to host temporary directory ---")
        write_multiple_files_to_host(mutations_data_for_writing, workdir)

        print(f"--- Evaluating {q} mutations with {args.workers} workers ---")
        losses = np.zeros(q)
        with ProcessPoolExecutor(max_workers=args.workers) as executor:
            results = executor.map(evaluate_mutation_on_host, tasks)
            for i, loss in enumerate(results):
                losses[i] = loss
                print(f"Evaluation progress: {i + 1}/{q}", end='\r')
        print("\nEvaluation complete.")

    finally:
        print("--- Batch removing temporary images from host ---")
        cleanup_pattern = os.path.join(workdir, f"temp_zo_{run_id}_*.png")
        remove_files_on_host_batch(cleanup_pattern)

    gradient = np.zeros_like(image, dtype=np.float32)
    for i in range(q):
        loss_positive = losses[i]
        noise = noise_vectors[i]
        gradient += (loss_positive - base_loss) * noise

    gradient /= (q * fd_eta)
    
    return gradient


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
        # It's okay if no model is provided when using raw_args_template, as long as the template doesn't need them.
        if args.raw_args_template and '{MODEL_PATHS}' in args.raw_args_template:
            raise ValueError("Raw args template contains '{MODEL_PATHS}' but no models were provided via --model or --models.")
        if not args.raw_args_template:
            raise ValueError("No model files provided. Use --model, --models, or --raw-args-template.")
        args.model_paths = [] # Set to empty list to avoid errors

    temp_dir_base = "/dev/shm" if os.path.exists("/dev/shm") else None
    workdir = tempfile.mkdtemp(prefix="zosignsgd_host_attack_", dir=temp_dir_base)
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
        
        # --- Log all parameters used for this run ---
        args_dict = vars(args)
        # Use default=str as a safeguard for any non-serializable types
        params_json = json.dumps(args_dict, indent=4, default=str)
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
        # Use the processed list of model paths for verification
        if args.raw_args_template:
            # For raw args, we check the executable from the template and any models passed separately.
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
            print("--- Detected Grayscale Image: Converting to 3-channel BGR for processing. ---")
            original_image = cv2.cvtColor(original_image, cv2.COLOR_GRAY2BGR)
        else:
            print("--- Detected Color Mode: Processing in 3-channel BGR mode. ---")

        print("--- Standardizing to RGB color space for attack consistency. ---")
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

        attack_image_for_zo = attack_image.copy()

        for i in range(args.iterations):
            iter_start_time = time.time()
            print(f"--- Iteration {i+1}/{args.iterations} (Total Queries: {total_queries}) ---")
            if args.enable_dynamic_focus:
                # current_focus_target can be a list now, handle printing
                targets_str = current_focus_target
                if isinstance(current_focus_target, list):
                    targets_str = ", ".join(current_focus_target)
                print(f"Current Mode: {attack_mode.upper()}. Focus Target(s): {targets_str if targets_str else 'N/A'}")

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
            if decay_reason:
                 print(f"New LR: {current_lr:.6f}")


            dynamic_weights = {addr: state["dynamic_weight"] for addr, state in hooks_attack_state.items()}
            grad = estimate_gradient_zosignsgd(attack_image_for_zo, args, hook_config, workdir, dynamic_weights)
            total_queries += args.num_queries + 1
            
            # ZO-Sign-SGD uses a sign-based update step, not Adam
            update_step = current_lr * np.sign(grad)
            attack_image_for_zo -= update_step

            perturbation = np.clip(attack_image_for_zo - original_image_float, -args.l_inf_norm, args.l_inf_norm)
            attack_image_for_zo = np.clip(original_image_float + perturbation, 0, 255)
            attack_image = attack_image_for_zo

            # Standardize to uint8 and create a BGR version for cv2 functions
            attack_image_uint8_rgb = attack_image.astype(np.uint8)
            attack_image_uint8_bgr = cv2.cvtColor(attack_image_uint8_rgb, cv2.COLOR_RGB2BGR)

            is_success_encoding, encoded_image = cv2.imencode(".png", attack_image_uint8_bgr)
            if not is_success_encoding:
                print("Warning: Failed to encode attack image for verification.")
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
            
            # Format hook details for logging
            hook_details_str = ""
            # Only record full hook details on the final iteration or on success
            if is_successful or (i == args.iterations - 1):
                hook_details_for_log = {
                    addr: {
                        "loss": round(float(diag.get("individual_loss", 0.0)), 6),
                        "satisfied": bool(diag.get("is_satisfied", False))
                    }
                    for addr, diag in hook_diagnostics.items()
                }
                hook_details_str = json.dumps(hook_details_for_log)

            # Format focus targets for logging
            targets_str = "N/A" # Default for static mode
            if args.enable_dynamic_focus:
                if isinstance(current_focus_target, list):
                    targets_str = ";".join(current_focus_target) if current_focus_target else "None"
                elif current_focus_target:
                    targets_str = current_focus_target
                else:
                    targets_str = "None"

            log_data = [
                i + 1,
                total_queries,
                f"{loss:.6f}",
                f"{best_loss_so_far:.6f}",
                f"{current_lr:.6f}",
                is_successful,
                num_satisfied_hooks,
                total_hooks,
                attack_mode,
                f'"{targets_str}"',
                f'"{hook_details_str}"',
                f"{iter_time:.2f}",
                f"{total_time_so_far:.2f}"
            ]
            detailed_log_file.write(",".join(map(str, log_data)) + "\n")
            detailed_log_file.flush()

            latest_image_path = os.path.join(args.output_dir, "latest_attack_image_zosignsgd_host.png")
            cv2.imwrite(latest_image_path, attack_image_uint8_bgr)

            if loss < best_loss_so_far:
                best_loss_so_far = loss
                print(f"New best loss found: {loss:.6f}. Saving best image.")
                best_image_path = os.path.join(args.output_dir, "best_attack_image_zosignsgd_host.png")
                cv2.imwrite(best_image_path, attack_image_uint8_bgr)

                print("--- Verifying current best image ---")
                best_image_output = get_executable_output(best_image_path, args)
                print("Execution Output on Current Best Image:")
                print(best_image_output)

                _, best_hooks, _ = _run_executable_and_parse_hooks(best_image_path, args)
                print("GDB Hook Info on Current Best Image (JSON):")
                print(json.dumps(best_hooks, indent=4))

            if args.enable_stagnation_decay:
                if loss < best_loss_for_stagnation - args.min_loss_delta:
                    best_loss_for_stagnation = loss
                    stagnation_patience_counter = 0
                else: 
                    stagnation_patience_counter += 1
                print(f"Stagnation patience: {stagnation_patience_counter}/{args.stagnation_patience}")

            if args.enable_dynamic_focus:
                if attack_mode == "scouting":
                    scouting_cycle_counter += 1
                    print(f"Scouting... Cycle {scouting_cycle_counter}/{args.evaluation_window}")

                    print("GDB Hook Info on Current Attack Image (Scouting Mode):")
                    print(json.dumps(current_hooks, indent=4))
                    if hooked_errors:
                        print("GDB Hook Errors on Current Attack Image (Scouting Mode):")
                        print(json.dumps(hooked_errors, indent=4))

                    print("  - Scouting loss changes this iteration:")
                    changed_hooks_count = 0
                    # Sort for consistent output order
                    for addr, diag in sorted(hook_diagnostics.items()):
                        if addr in hooks_attack_state:
                            state = hooks_attack_state[addr]
                            current_loss = diag["individual_loss"]
                            if state["loss_history"]: # Check if history is not empty
                                previous_loss = state["loss_history"][-1]
                                if not np.isclose(current_loss, previous_loss, atol=1e-5):
                                    print(f"    - Hook {addr}: loss changed from {previous_loss:.6f} -> {current_loss:.6f}")
                                    changed_hooks_count += 1
                            else:
                                print(f"    - Hook {addr}: initial scouting loss is {current_loss:.6f}")
                                changed_hooks_count += 1
                    
                    if changed_hooks_count == 0:
                        print("    - No significant loss changes detected for any hook.")

                    for addr, state in hooks_attack_state.items():
                        if addr in hook_diagnostics:
                            state["loss_history"].append(hook_diagnostics[addr]["individual_loss"])

                    if scouting_cycle_counter >= args.evaluation_window:
                        print(f"\n--- End of Scouting Window. Analyzing results... ---")
                        
                        for addr, state in hooks_attack_state.items():
                            if len(state["loss_history"]) > 1:
                                indices = np.arange(len(state["loss_history"]))
                                slope, _, _, _, _ = stats.linregress(indices, state["loss_history"])
                                state["descent_rate"] = -slope # Slope is negative for descent, so we use its negation
                            else:
                                state["descent_rate"] = 0.0
                        
                        # Find all hooks that are making significant progress
                        progressing_targets = []
                        descent_threshold = args.min_loss_delta
                        print(f"Identifying targets with descent rate > {descent_threshold:.6f} (min_loss_delta)")
                        for addr, state in hooks_attack_state.items():
                            if addr in hook_diagnostics and not hook_diagnostics[addr]["is_satisfied"]:
                                if state["descent_rate"] > descent_threshold:
                                    print(f"  - Candidate: {addr} (Descent Rate: {state['descent_rate']:.6f}/iter)")
                                    progressing_targets.append(addr)
                        
                        scouting_cycle_counter = 0
                        for state in hooks_attack_state.values():
                            state["loss_history"] = []

                        if progressing_targets:
                            current_focus_target = progressing_targets
                            attack_mode = "focused_fire"
                            print(f"FOCUS SHIFT: New targets are '{', '.join(current_focus_target)}'.")
                            
                            print("--- Updating hook weights for FOCUSED_FIRE mode ---")
                            for addr, state in hooks_attack_state.items():
                                state["consecutive_satisfaction_count"] = 0 # Reset counter
                                is_satisfied = hook_diagnostics.get(addr, {}).get("is_satisfied", False)

                                if addr in current_focus_target:
                                    state["dynamic_weight"] = args.boost_weight
                                    print(f"  - Hook {addr}: Is a FOCUS TARGET. Boosting weight to {args.boost_weight}.")
                                elif is_satisfied:
                                    state["dynamic_weight"] = args.satisfied_weight
                                    print(f"  - Hook {addr}: Is SATISFIED. Assigning maintenance weight {args.satisfied_weight}.")
                                else:
                                    state["dynamic_weight"] = args.non_target_weight
                                    print(f"  - Hook {addr}: Non-target. Setting weight to {args.non_target_weight}.")

                            print(f"Switching to FOCUSED_FIRE mode. Weights updated.")
                            
                            if args.enable_stagnation_decay:
                                print("--- Resetting stagnation tracker due to mode switch. ---")
                                stagnation_patience_counter = 0
                                best_loss_for_stagnation = float('inf')
                        else:
                            print("No hooks showed significant progress. Remaining in SCOUTING mode.")
                
                elif attack_mode == "focused_fire":
                    print("GDB Hook Info on Current Attack Image (Focused Fire Mode):")
                    print(json.dumps(current_hooks, indent=4))
                    if hooked_errors:
                        print("GDB Hook Errors on Current Attack Image (Focused Fire Mode):")
                        print(json.dumps(hooked_errors, indent=4))

                    # New logic for target retirement
                    print("--- Updating hook weights and checking targets within FOCUSED_FIRE mode ---")
                    if not current_focus_target or not isinstance(current_focus_target, list):
                        # Safety check, if no targets, switch back to scouting
                        attack_mode = "scouting"
                        print("No focus targets found, switching back to SCOUTING.")
                    else:
                        still_active_targets = []
                        for target in current_focus_target:
                            is_satisfied = hook_diagnostics.get(target, {}).get("is_satisfied", False)
                            
                            if is_satisfied:
                                hooks_attack_state[target]["consecutive_satisfaction_count"] += 1
                                print(f"  - Target {target}: SATISFIED. Consecutive count: {hooks_attack_state[target]['consecutive_satisfaction_count']}/{args.satisfaction_patience}.")
                            else:
                                if hooks_attack_state[target]["consecutive_satisfaction_count"] > 0:
                                    print(f"  - Target {target}: Became UNSATISFIED. Resetting satisfaction count.")
                                hooks_attack_state[target]["consecutive_satisfaction_count"] = 0

                            # Check for retirement
                            if hooks_attack_state[target]["consecutive_satisfaction_count"] >= args.satisfaction_patience:
                                print(f"  - Target {target}: RETIRED. Assigning satisfied maintenance weight: {args.satisfied_weight}.")
                                hooks_attack_state[target]["dynamic_weight"] = args.satisfied_weight
                            else:
                                still_active_targets.append(target)
                                # Keep weight boosted if it's still an active target
                                if hooks_attack_state[target]["dynamic_weight"] != args.boost_weight:
                                    print(f"  - Target {target}: NOT yet retired. Boosting weight to {args.boost_weight}.")
                                    hooks_attack_state[target]["dynamic_weight"] = args.boost_weight
                        
                        current_focus_target = still_active_targets

                        # If all targets are retired, switch back to scouting mode
                        if not current_focus_target:
                            print(f"\n--- ALL TARGETS RETIRED! ---")
                            
                            attack_mode = "scouting"
                            print("Switching back to SCOUTING mode to find the next target.")

                            current_focus_target = None
                            scouting_cycle_counter = 0
                            
                            if args.enable_stagnation_decay:
                                print("--- Resetting stagnation tracker due to mode switch. ---")
                                stagnation_patience_counter = 0
                                best_loss_for_stagnation = float('inf')

                            # Reset all hooks for the new scouting phase
                            for addr, state in hooks_attack_state.items():
                                # In scouting mode, give satisfied hooks a maintenance weight and others a baseline weight.
                                is_satisfied = hook_diagnostics.get(addr, {}).get("is_satisfied", False)
                                if is_satisfied:
                                    state["dynamic_weight"] = args.satisfied_weight
                                else:
                                    state["dynamic_weight"] = args.non_target_weight
                                
                                state["loss_history"] = []
                                state["descent_rate"] = 0.0
                                state["consecutive_satisfaction_count"] = 0

            if is_successful:
                print("\nAttack successful according to GDB hooks!")
                successful_image_path = os.path.join(args.output_dir, "successful_attack_image_zosignsgd_host.png")
                cv2.imwrite(successful_image_path, attack_image_uint8_bgr)
                print(f"Adversarial image saved to: {successful_image_path}")
                
                print("\n--- Verifying final image by direct execution (without GDB) ---")
                final_output = get_executable_output(successful_image_path, args)
                print("Execution Output on Successful Image:")
                print(final_output)

                if "true" in final_output.lower():
                    print("--- Verification PASSED: Direct execution confirms success. ---")
                else:
                    print("--- Verification FAILED: Direct execution does not confirm success. The attack may be incomplete. ---")

                _, final_hooks, _ = _run_executable_and_parse_hooks(successful_image_path, args)
                print("GDB Hook Info on Successful Image (JSON):")
                print(json.dumps(final_hooks, indent=4))
                
                break

    except (FileNotFoundError, RuntimeError, ValueError) as e:
        print(f"\nAn error occurred: {e}")
        if attack_image is not None:
            print("Interrupt received. Saving the last generated image...")
            interrupted_image_path = os.path.join(args.output_dir, "interrupted_attack_image_zosignsgd_host.png")
            cv2.imwrite(interrupted_image_path, cv2.cvtColor(attack_image.astype(np.uint8), cv2.COLOR_RGB2BGR))
            print(f"Last image saved to: {interrupted_image_path}")
    finally:
        if detailed_log_file:
            detailed_log_file.close()
        if workdir and os.path.exists(workdir):
            shutil.rmtree(workdir)
            print(f"Temporary directory {workdir} cleaned up.")
        print("Cleanup finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A grey-box adversarial attack using ZO-Sign-SGD (Targetless Host Version).")
    # Make executable optional at the argparse level; we'll validate it manually.
    parser.add_argument("--executable", help="Local path to the target executable. Required if not using --raw-args-template.")
    parser.add_argument("--image", required=True, help="Local path to the initial image to be attacked.")
    parser.add_argument("--hooks", required=True, help="Local path to the JSON file defining hook points and loss conditions.")
    parser.add_argument("--model", nargs='+', help="One or more local paths to model files. Use for one model or when paths don't contain commas.")
    parser.add_argument("--models", type=str, help="A comma-separated string of model file paths. Use for multiple models like fsanet.")
    parser.add_argument("--iterations", type=int, default=100, help="Maximum number of attack iterations.")
    parser.add_argument("--learning-rate", type=float, default=20.0, help="Initial learning rate for the attack.")
    parser.add_argument("--l-inf-norm", type=float, default=20.0, help="Maximum L-infinity norm for the perturbation.")
    parser.add_argument("--lr-decay-rate", type=float, default=0.97, help="Learning rate decay rate.")
    parser.add_argument("--lr-decay-steps", type=int, default=10, help="Decay learning rate every N steps.")
    parser.add_argument("--missing-hook-penalty", type=float, default=10.0, help="Penalty to apply when a configured hook is not triggered.")
    parser.add_argument("--margin", type=float, default=0.05, help="A margin for the loss function to create more robust attacks.")
    
    zo_group = parser.add_argument_group("ZO-Sign-SGD Parameters")
    zo_group.add_argument("--num-queries", "-q", type=int, default=100, help="Number of random directions to query per iteration.")
    zo_group.add_argument("--fd-eta", type=float, default=0.15, help="Finite difference step size (exploration magnitude).")
    
    stagnation_group = parser.add_argument_group("Stagnation-based Decay")
    stagnation_group.add_argument("--enable-stagnation-decay", action="store_true", help="Enable learning rate decay when loss stagnates.")
    stagnation_group.add_argument("--stagnation-patience", type=int, default=20, help="Iterations with no improvement before forcing a decay.")
    stagnation_group.add_argument("--min-loss-delta", type=float, default=0.001, help="Minimum change in loss to be considered an improvement for stagnation.")

    dynamic_focus_group = parser.add_argument_group("Dynamic Focus Strategy (Event-Driven)")
    dynamic_focus_group.add_argument("--enable-dynamic-focus", action="store_true", help="Enable the dynamic, event-driven attack strategy.")
    dynamic_focus_group.add_argument("--evaluation-window", type=int, default=10, help="[Dynamic Focus] Number of iterations in one 'scouting' window.")
    dynamic_focus_group.add_argument("--boost-weight", type=float, default=10.0, help="[Dynamic Focus] High weight applied to the focused hook.")
    dynamic_focus_group.add_argument("--non-target-weight", type=float, default=1.0, help="[Dynamic Focus] Baseline weight for non-focused hooks.")
    dynamic_focus_group.add_argument("--satisfied-weight", type=float, default=3.0, help="[Dynamic Focus] Weight for satisfied, non-focused hooks to maintain their state.")
    dynamic_focus_group.add_argument("--satisfaction-threshold", type=float, default=0.01, help="[Dynamic Focus] Loss threshold below which a hook is considered 'satisfied'.")
    dynamic_focus_group.add_argument("--satisfaction-patience", type=int, default=3, help="[Dynamic Focus] Iterations a target must be satisfied consecutively before being retired.")

    custom_command_group = parser.add_argument_group("Custom Command Execution")
    custom_command_group.add_argument("--raw-args-template", type=str, help="A raw command line template for executables with complex arguments. Use {IMAGE_PATH} as a placeholder for the attack image and {MODEL_PATHS} for models provided via --model(s). E.g., './face_analysis_cli {MODEL_PATHS} analyze {IMAGE_PATH} out.bin'. This overrides --executable.")

    parser.add_argument("--workers", type=int, default=os.cpu_count(), help="Number of parallel processes for evaluation.")
    parser.add_argument("--output-dir", type=str, default="attack_outputs_zosignsgd_host", help="Directory to save output images and logs.")
    
    cli_args = parser.parse_args()
    
    # --- Manual Validation for Executable ---
    if not cli_args.raw_args_template and not cli_args.executable:
        parser.error("Either --executable or --raw-args-template must be provided.")

    main(cli_args) 
