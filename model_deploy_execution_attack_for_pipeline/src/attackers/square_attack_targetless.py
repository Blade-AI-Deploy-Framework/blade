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
    
    # Use a fixed weight of 1.0 for all hooks as Square Attack is gradient-free
    # and does not use the dynamic weighting strategy.
    dynamic_weights = {hook.get("address"): 1.0 for hook in hook_config}

    for hook_info in hook_config:
        address = hook_info.get("address")
        branch_instruction = hook_info.get("original_branch_instruction")
        
        if not all([address, branch_instruction]):
            continue

        dynamic_weight = dynamic_weights.get(address, 1.0)

        if verbose:
            print(f"Hook at {address}:")
            print(f"  - Branch Condition: '{branch_instruction}'")

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
            if branch_instruction in ["b.gt", "b.hi", "b.ge", "b.hs", "b.cs", "b.pl"]:
                pair_loss = np.maximum(0, (v1 - v2) + margin)
                if verbose: formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})"
            elif branch_instruction in ["b.lt", "b.lo", "b.cc", "b.mi", "b.le", "b.ls"]:
                pair_loss = np.maximum(0, (v2 - v1) + margin)
                if verbose: formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})"
            elif branch_instruction == "b.eq":
                pair_loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
                if verbose: formula = f"max(0, {margin} - abs({v1:.4f} - {v2:.4f}))^2"
            elif branch_instruction == "b.ne":
                pair_loss = (v1 - v2) ** 2
                if verbose: formula = f"({v1:.4f} - {v2:.4f})^2"
            else:
                return 0.0
        else:  # attack_mode == 'satisfy'
            if branch_instruction in ["b.gt", "b.hi", "b.ge", "b.hs", "b.cs", "b.pl"]:
                pair_loss = np.maximum(0, (v2 - v1) + margin)
                if verbose: formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})"
            elif branch_instruction in ["b.lt", "b.lo", "b.cc", "b.mi", "b.le", "b.ls"]:
                pair_loss = np.maximum(0, (v1 - v2) + margin)
                if verbose: formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})"
            elif branch_instruction == "b.eq":
                pair_loss = (v1 - v2) ** 2
                if verbose: formula = f"({v1:.4f} - {v2:.4f})^2"
            elif branch_instruction == "b.ne":
                pair_loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
                if verbose: formula = f"max(0, {margin} - abs({v1:.4f} - {v2:.4f}))^2"
            else:
                return 0.0 # Return 0 loss for this pair
    else:
        pair_loss = missing_hook_penalty
        if verbose:
            print(f"  - Pair #{pair_index}: Not found in captured values ({len(values)} total). Applying penalty.")
    
    if verbose and formula != "N/A":
        print(f"    - Formula: {formula}")
        print(f"    - Pair Loss: {pair_loss:.6f}")
        
    return pair_loss

def p_selection(p_init, it, n_iters):
    """ Piece-wise constant schedule for p (the fraction of pixels changed on every iteration). """
    it = int(it / n_iters * 10000)

    if 10 < it <= 50:
        p = p_init / 2
    elif 50 < it <= 200:
        p = p_init / 4
    elif 200 < it <= 500:
        p = p_init / 8
    elif 500 < it <= 1000:
        p = p_init / 16
    elif 1000 < it <= 2000:
        p = p_init / 32
    elif 2000 < it <= 4000:
        p = p_init / 64
    elif 4000 < it <= 6000:
        p = p_init / 128
    elif 6000 < it <= 8000:
        p = p_init / 256
    elif 8000 < it <= 10000:
        p = p_init / 512
    else:
        p = p_init

    return p

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
    workdir = tempfile.mkdtemp(prefix="square_host_attack_", dir=temp_dir_base)
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
            "iteration", "total_queries", "loss", "best_loss", 
            "is_successful_iter", "num_satisfied_hooks", "total_hooks",
            "hook_details", "iter_time_s", "total_time_s"
        ]
        detailed_log_file.write(",".join(log_header) + "\n")
        print(f"--- Detailed metrics will be logged to: {detailed_log_path} ---")

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

        original_image = cv2.imread(args.image, cv2.IMREAD_COLOR)
        if original_image is None:
            raise FileNotFoundError(f"Could not read original image: {args.image}")

        if original_image.ndim == 2:
            original_image = cv2.cvtColor(original_image, cv2.COLOR_GRAY2BGR)
        
        original_image = cv2.cvtColor(original_image, cv2.COLOR_BGR2RGB)
        
        print("\n--- Starting Attack Loop (Square Attack) ---")
        
        original_image_float = original_image.astype(np.float32)
        h, w, c = original_image.shape
        n_features = c * h * w

        # Initialize perturbation
        init_perturb = np.random.choice([-args.l_inf_norm, args.l_inf_norm], size=original_image_float.shape)
        attack_image = np.clip(original_image_float + init_perturb, 0, 255)
        
        attack_image_uint8_rgb = attack_image.astype(np.uint8)
        attack_image_uint8_bgr = cv2.cvtColor(attack_image_uint8_rgb, cv2.COLOR_RGB2BGR)
        is_success_encoding, encoded_image = cv2.imencode(".png", attack_image_uint8_bgr)
        
        is_successful, current_hooks, hooked_errors = run_attack_iteration(encoded_image.tobytes(), args, workdir, "temp_attack_image.png")
        total_queries += 1
        loss, hook_diagnostics = calculate_targetless_loss(current_hooks, hook_config, {}, args.satisfaction_threshold, margin=args.margin, missing_hook_penalty=args.missing_hook_penalty)
        best_loss_so_far = loss
        
        print(f"Initial loss: {best_loss_so_far:.6f}")

        for i in range(args.iterations):
            iter_start_time = time.time()
            print(f"--- Iteration {i+1}/{args.iterations} (Total Queries: {total_queries}) ---")

            # Determine patch size for this iteration
            p = p_selection(args.p_init, i, args.iterations)
            s = int(round(np.sqrt(p * n_features / c)))
            s = min(max(s, 1), h - 1)

            # Choose random location for the patch
            center_h = np.random.randint(0, h - s)
            center_w = np.random.randint(0, w - s)
            
            # Create a new perturbation attempt
            current_perturbation = attack_image - original_image_float
            new_perturbation = current_perturbation.copy()
            
            # Generate random sign flips for the patch
            rand_signs = np.random.choice([-1, 1], size=(c,)) * args.l_inf_norm
            new_perturbation[center_h:center_h+s, center_w:center_w+s, :] = rand_signs

            new_attack_image = np.clip(original_image_float + new_perturbation, 0, 255)

            # Evaluate the new image
            new_attack_image_uint8_rgb = new_attack_image.astype(np.uint8)
            new_attack_image_uint8_bgr = cv2.cvtColor(new_attack_image_uint8_rgb, cv2.COLOR_RGB2BGR)
            is_success_encoding, encoded_image = cv2.imencode(".png", new_attack_image_uint8_bgr)
            
            if not is_success_encoding:
                print("Warning: Failed to encode attack image for verification.")
                continue

            is_successful, current_hooks, hooked_errors = run_attack_iteration(encoded_image.tobytes(), args, workdir, "temp_attack_image.png")
            total_queries += 1
            loss, hook_diagnostics = calculate_targetless_loss(current_hooks, hook_config, {}, args.satisfaction_threshold, margin=args.margin, missing_hook_penalty=args.missing_hook_penalty)
            
            # If the loss improved, accept the new image
            if loss < best_loss_so_far:
                print(f"Loss improved from {best_loss_so_far:.6f} to {loss:.6f}. Accepting change.")
                attack_image = new_attack_image
                best_loss_so_far = loss
            else:
                print(f"Loss did not improve ({loss:.6f} vs best {best_loss_so_far:.6f}). Rejecting change.")

            iter_time = time.time() - iter_start_time
            total_time_so_far = time.time() - start_time
            print(f"Attack result: {'Success' if is_successful else 'Fail'}. Best Loss: {best_loss_so_far:.6f}. Iter Time: {iter_time:.2f}s. Total Time: {total_time_so_far:.2f}s")
            
            num_satisfied_hooks = sum(1 for d in hook_diagnostics.values() if d.get("is_satisfied", False))
            total_hooks = len(hook_config)
            
            hook_details_str = ""
            if is_successful or (i == args.iterations - 1):
                hook_details_for_log = {
                    addr: {"loss": round(float(diag.get("individual_loss", 0.0)), 6), "satisfied": bool(diag.get("is_satisfied", False))}
                    for addr, diag in hook_diagnostics.items()
                }
                hook_details_str = json.dumps(hook_details_for_log)

            log_data = [
                i + 1, total_queries, f"{loss:.6f}", f"{best_loss_so_far:.6f}",
                is_successful, num_satisfied_hooks, total_hooks,
                f'"{hook_details_str}"', f"{iter_time:.2f}", f"{total_time_so_far:.2f}"
            ]
            detailed_log_file.write(",".join(map(str, log_data)) + "\n")
            detailed_log_file.flush()

            attack_image_uint8_bgr = cv2.cvtColor(attack_image.astype(np.uint8), cv2.COLOR_RGB2BGR)
            latest_image_path = os.path.join(args.output_dir, "latest_attack_image_square_host.png")
            cv2.imwrite(latest_image_path, attack_image_uint8_bgr)

            if loss == best_loss_so_far:
                best_image_path = os.path.join(args.output_dir, "best_attack_image_square_host.png")
                cv2.imwrite(best_image_path, attack_image_uint8_bgr)

            if is_successful:
                print("\nAttack successful according to GDB hooks!")
                successful_image_path = os.path.join(args.output_dir, "successful_attack_image_square_host.png")
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
            interrupted_image_path = os.path.join(args.output_dir, "interrupted_attack_image_square_host.png")
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
    parser = argparse.ArgumentParser(description="A grey-box adversarial attack using Square Attack (Targetless Host Version).")
    parser.add_argument("--executable", help="Local path to the target executable. Required if not using --raw-args-template.")
    parser.add_argument("--image", required=True, help="Local path to the initial image to be attacked.")
    parser.add_argument("--hooks", required=True, help="Local path to the JSON file defining hook points and loss conditions.")
    parser.add_argument("--model", nargs='+', help="One or more local paths to model files.")
    parser.add_argument("--models", type=str, help="A comma-separated string of model file paths.")
    parser.add_argument("--iterations", type=int, default=10000, help="Maximum number of attack iterations (queries).")
    parser.add_argument("--l-inf-norm", type=float, default=20.0, help="Maximum L-infinity norm for the perturbation.")
    parser.add_argument("--missing-hook-penalty", type=float, default=10.0, help="Penalty to apply when a configured hook is not triggered.")
    parser.add_argument("--margin", type=float, default=0.05, help="A margin for the loss function to create more robust attacks.")
    parser.add_argument("--p-init", type=float, default=0.1, help="Initial fraction of features to perturb.")
    parser.add_argument("--satisfaction-threshold", type=float, default=0.01, help="Loss threshold below which a hook is considered 'satisfied'.")
    
    custom_command_group = parser.add_argument_group("Custom Command Execution")
    custom_command_group.add_argument("--raw-args-template", type=str, help="A raw command line template for executables with complex arguments. Use {IMAGE_PATH} and {MODEL_PATHS} as placeholders.")

    parser.add_argument("--workers", type=int, default=os.cpu_count(), help="Number of parallel processes for evaluation (used for initial setup).")
    parser.add_argument("--output-dir", type=str, default="attack_outputs_square_host", help="Directory to save output images and logs.")
    
    cli_args = parser.parse_args()
    
    if not cli_args.raw_args_template and not cli_args.executable:
        parser.error("Either --executable or --raw-args-template must be provided.")

    main(cli_args)
