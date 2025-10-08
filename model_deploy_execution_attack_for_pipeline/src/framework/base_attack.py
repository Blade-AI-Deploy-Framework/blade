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
import abc
from collections import deque

# ==============================================================================
# Top-level Helper Functions for Multiprocessing
# ==============================================================================

def _run_executable_and_parse_hooks(image_path_on_host, args, model_paths):
    """
    Runs the target executable with GDB and parses hook results.
    This is a top-level function to be safely used by multiprocessing workers.
    """
    script_path = os.path.join(os.path.dirname(__file__), "run_gdb_host.sh") 
    
    if args.raw_args_template:
        model_paths_str = ' '.join([os.path.abspath(p) for p in model_paths])
        command_template = args.raw_args_template.replace('{MODEL_PATHS}', model_paths_str)
        command_template = command_template.replace('{IMAGE_PATH}', os.path.abspath(image_path_on_host))
        executable_and_args = shlex.split(command_template)
        executable_and_args[0] = os.path.abspath(executable_and_args[0])
        command = ['/bin/bash', script_path, *executable_and_args, os.path.abspath(args.hooks)]
    else:
        model_paths_on_host = [os.path.abspath(p) for p in model_paths]
        command = ['/bin/bash', script_path, os.path.abspath(args.executable), *model_paths_on_host, os.path.abspath(image_path_on_host), os.path.abspath(args.hooks)]

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
        stderr = e.stderr if hasattr(e, 'stderr') else "Timeout or error"
        print(f"Error running host executable for '{image_path_on_host}': {stderr}")
        return False, {}, {}

    hooked_values, hooked_errors, is_successful = {}, {}, False
    full_output = result.stdout + "\n" + result.stderr
    
    for line in full_output.splitlines():
        if "true" in line and "HOOK_RESULT" not in line: is_successful = True
        if "HOOK_RESULT" in line:
            match = re.search(r'offset=(0x[0-9a-fA-F]+)\s+.*value=(.*)', line)
            if not match: continue
            offset, val_str = match.groups()
            try:
                value = float(re.search(r'f\s*=\s*([-\d.e+]+)', val_str).group(1)) if val_str.startswith('{') else float(val_str.strip())
                hooked_values.setdefault(offset, []).append(value)
            except (ValueError, TypeError, AttributeError): pass
        elif "HOOK_ERROR" in line:
            match = re.search(r'offset=(0x[0-9a-fA-F]+)\s+register=([\w\d]+)\s+reason="(.*)"', line)
            if not match: continue
            offset, register, reason = match.groups()
            hooked_errors.setdefault(offset, []).append(f"Failed to read register '{register}': {reason}")
                
    return is_successful, hooked_values, hooked_errors

def _calculate_loss_for_one_pair(values, pair_index, attack_mode, branch, margin, penalty):
    idx1, idx2 = (pair_index - 1) * 2, (pair_index - 1) * 2 + 1
    
    if len(values) <= idx2:
        return penalty

    v1, v2 = values[idx1], values[idx2]
    loss = 0.0
    
    gt_cond = ["b.gt", "b.hi", "b.ge", "b.hs", "b.cs", "b.pl"]
    lt_cond = ["b.lt", "b.lo", "b.cc", "b.mi", "b.le", "b.ls"]

    if attack_mode == 'invert':
        if branch in gt_cond: loss = np.maximum(0, (v1 - v2) + margin)
        elif branch in lt_cond: loss = np.maximum(0, (v2 - v1) + margin)
        elif branch == "b.eq": loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
        elif branch == "b.ne": loss = (v1 - v2) ** 2
    else:  # satisfy
        if branch in gt_cond: loss = np.maximum(0, (v2 - v1) + margin)
        elif branch in lt_cond: loss = np.maximum(0, (v1 - v2) + margin)
        elif branch == "b.eq": loss = (v1 - v2) ** 2
        elif branch == "b.ne": loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
    
    return loss

def _calculate_targetless_loss(current_hooks, hook_config, dynamic_weights, satisfaction_threshold, margin=0.01, missing_hook_penalty=10.0, verbose=False):
    if verbose:
        print("\n" + "="*50 + "\n--- Loss Function Analysis ---\n" + "="*50)

    if not isinstance(current_hooks, dict):
        if verbose: print("Warning: Hook values are not a valid dictionary. Applying penalty.")
        return len(hook_config) * missing_hook_penalty if hook_config else float('inf'), {}

    total_loss, hook_diagnostics = 0.0, {}
    
    for hook_info in hook_config:
        address, branch_instruction = hook_info.get("address"), hook_info.get("original_branch_instruction")
        if not all([address, branch_instruction]): continue

        dynamic_weight = dynamic_weights.get(address, 1.0)
        values = current_hooks.get(address)
        hook_loss_sum = 0.0

        if "pairs_to_process" in hook_info:
            pairs_config = hook_info["pairs_to_process"]
            if values is None:
                hook_loss_sum = missing_hook_penalty * len(pairs_config)
            else:
                for pair_cfg in pairs_config:
                    hook_loss_sum += _calculate_loss_for_one_pair(values, pair_cfg["pair_index"], pair_cfg.get("attack_mode", "satisfy"), branch_instruction, margin, missing_hook_penalty)
        else:
            pair_indices = hook_info.get("value_pairs", [1])
            attack_mode = hook_info.get("attack_mode", "satisfy")
            if values is None:
                hook_loss_sum = missing_hook_penalty * len(pair_indices)
            else:
                for pair_index in pair_indices:
                    hook_loss_sum += _calculate_loss_for_one_pair(values, pair_index, attack_mode, branch_instruction, margin, missing_hook_penalty)

        total_loss += hook_loss_sum * dynamic_weight
        hook_diagnostics[address] = {"individual_loss": hook_loss_sum, "is_satisfied": hook_loss_sum < satisfaction_threshold}

    if verbose:
        print(f"\nTotal Loss (Sum): {total_loss:.6f}\n" + "="*50)

    return total_loss, hook_diagnostics

def _evaluate_mutation_on_host_for_pool(task_args):
    """
    Wrapper for instance method to be used by ProcessPoolExecutor.
    """
    image_path_on_host, hook_config, dynamic_weights, args_dict = task_args
    
    class ArgsHolder:
        def __init__(self, d): self.__dict__.update(d)
    args = ArgsHolder(args_dict)

    if args.models:
        model_paths = [p.strip() for p in args.models.split(',')]
    elif args.model:
        model_paths = args.model
    else:
        model_paths = []
    
    _, hooks, _ = _run_executable_and_parse_hooks(image_path_on_host, args, model_paths)
    loss, _ = _calculate_targetless_loss(hooks, hook_config, dynamic_weights, args.satisfaction_threshold, margin=args.margin, missing_hook_penalty=args.missing_hook_penalty)
    return loss

# ==============================================================================
# Abstract Base Class for Attacks
# ==============================================================================

class BaseAttack(abc.ABC):
    """
    An abstract base class for targetless, grey-box adversarial attacks.
    """
    def __init__(self, args):
        self.args = args
        
        # --- Attack State ---
        self.attack_image = None
        self.original_image_float = None
        self.best_loss_so_far = float('inf')
        self.best_image_path = None
        self.total_queries = 0
        self.workdir = None
        self.detailed_log_file = None
        
        # --- Dynamic Strategy State ---
        self.hooks_attack_state = {}
        self.attack_mode = "scouting" if self.args.enable_dynamic_focus else "static"
        self.current_focus_target = None
        self.scouting_cycle_counter = 0

        # --- LR Decay State ---
        self.stagnation_patience_counter = 0
        self.iteration_of_last_decay = 0
        self.total_decay_count = 0
        self.best_loss_for_stagnation = float('inf')
        self.current_lr = self.args.learning_rate if hasattr(self.args, 'learning_rate') else 0
        
    @staticmethod
    def add_common_args(parser):
        """Adds arguments common to all attack types."""
        common_group = parser.add_argument_group("Common Attack Parameters")
        common_group.add_argument("--executable", help="Local path to the target executable. Required if not using --raw-args-template.")
        common_group.add_argument("--image", required=True, help="Local path to the initial image to be attacked.")
        common_group.add_argument("--hooks", required=True, help="Local path to the JSON file defining hook points and loss conditions.")
        common_group.add_argument("--model", nargs='+', help="One or more local paths to model files. Use for one model or when paths don't contain commas.")
        common_group.add_argument("--models", type=str, help="A comma-separated string of model file paths. Use for multiple models like fsanet.")
        common_group.add_argument("--iterations", type=int, default=100, help="Maximum number of attack iterations.")
        common_group.add_argument("--l-inf-norm", type=float, default=20.0, help="Maximum L-infinity norm for the perturbation.")
        common_group.add_argument("--missing-hook-penalty", type=float, default=10.0, help="Penalty to apply when a configured hook is not triggered.")
        common_group.add_argument("--margin", type=float, default=0.05, help="A margin for the loss function to create more robust attacks.")
        
        stagnation_group = parser.add_argument_group("Stagnation-based Decay")
        stagnation_group.add_argument("--enable-stagnation-decay", action="store_true", help="Enable learning rate decay when loss stagnates.")
        stagnation_group.add_argument("--learning-rate", type=float, default=20.0, help="Initial learning rate for the attack.")
        stagnation_group.add_argument("--lr-decay-rate", type=float, default=0.97, help="Learning rate decay rate.")
        stagnation_group.add_argument("--lr-decay-steps", type=int, default=10, help="Decay learning rate every N steps.")
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

        exec_group = parser.add_argument_group("Execution Settings")
        exec_group.add_argument("--workers", type=int, default=os.cpu_count(), help="Number of parallel processes for evaluation.")
        exec_group.add_argument("--output-dir", type=str, default="attack_outputs", help="Directory to save output images and logs.")

    @staticmethod
    @abc.abstractmethod
    def add_attack_args(parser):
        """Add algorithm-specific arguments to the parser."""
        raise NotImplementedError

    @abc.abstractmethod
    def setup_attack(self):
        """Initialize attack-specific variables before the main loop."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_attack_candidate(self, iteration):
        """
        Generates a new candidate image for evaluation.
        
        Returns:
            tuple: A tuple containing:
                - candidate_image (np.ndarray): The new image to evaluate.
                - queries_made (int): The number of queries used to generate the candidate.
        """
        raise NotImplementedError
    
    @abc.abstractmethod
    def accept_candidate(self, candidate_image, loss, is_successful, hook_diagnostics):
        """
        Decides whether to accept the candidate image based on its evaluation.
        This method is responsible for updating `self.attack_image`.
        """
        raise NotImplementedError

    def run(self):
        """The main orchestrator for the attack."""
        start_time = time.time()
        
        try:
            os.setpgrp()
        except OSError:
            pass

        def sigint_handler(signum, frame):
            print("\nCtrl+C detected. Forcefully terminating all processes.")
            os.killpg(os.getpgrp(), signal.SIGKILL)

        signal.signal(signal.SIGINT, sigint_handler)
        
        try:
            self._setup_environment()
            self._load_resources()
            
            # --- Initial Evaluation ---
            print("\n--- Calculating initial loss for original image ---")
            is_success_encoding, encoded_original_image = cv2.imencode(".png", cv2.cvtColor(self.attack_image.astype(np.uint8), cv2.COLOR_RGB2BGR))
            if not is_success_encoding:
                raise RuntimeError("Failed to encode original image for initial analysis.")
            
            dynamic_weights = {addr: state["dynamic_weight"] for addr, state in self.hooks_attack_state.items()}
            _, initial_hooks, _ = self._run_attack_iteration(encoded_original_image.tobytes(), "initial_image_check.png")
            self.total_queries += 1
            
            initial_loss, _ = _calculate_targetless_loss(initial_hooks, self.hook_config, dynamic_weights, self.args.satisfaction_threshold, margin=self.args.margin, missing_hook_penalty=self.args.missing_hook_penalty, verbose=True)
            self.best_loss_so_far = initial_loss
            print(f"Initial loss: {self.best_loss_so_far:.6f}")

            self.setup_attack()

            print("\n--- Starting Attack Loop ---")
            for i in range(self.args.iterations):
                iter_start_time = time.time()
                print(f"--- Iteration {i+1}/{self.args.iterations} (Total Queries: {self.total_queries}) ---")

                self._update_learning_rate(i)

                candidate_image, queries_made = self.get_attack_candidate(i)
                self.total_queries += queries_made
                
                # --- Evaluate Candidate ---
                is_successful, current_hooks, hooked_errors, loss, hook_diagnostics = self._evaluate_image(candidate_image)
                self.total_queries += 1

                self.accept_candidate(candidate_image, loss, is_successful, hook_diagnostics)

                # --- Logging and Saving ---
                iter_time = time.time() - iter_start_time
                total_time_so_far = time.time() - start_time
                print(f"Attack result: {'Success' if is_successful else 'Fail'}. Loss: {loss:.6f}. Best Loss: {self.best_loss_so_far:.6f}. Iter Time: {iter_time:.2f}s. Total Time: {total_time_so_far:.2f}s")
                
                self._log_iteration_details(i, loss, is_successful, hook_diagnostics, iter_time, total_time_so_far)
                self._save_images(loss)

                if self.args.enable_stagnation_decay:
                    self._update_stagnation_counter(loss)
                
                if self.args.enable_dynamic_focus:
                    self._update_dynamic_focus(hook_diagnostics)

                if is_successful:
                    self._handle_success()
                    break

        except (FileNotFoundError, RuntimeError, ValueError) as e:
            print(f"\nAn error occurred: {e}")
            if self.attack_image is not None:
                print("Interrupt received. Saving the last generated image...")
                interrupted_image_path = os.path.join(self.args.output_dir, f"interrupted_attack_image_{self.args.attack_type}.png")
                cv2.imwrite(interrupted_image_path, cv2.cvtColor(self.attack_image.astype(np.uint8), cv2.COLOR_RGB2BGR))
                print(f"Last image saved to: {interrupted_image_path}")
        finally:
            self._cleanup()

    # --- Private Helper Methods ---

    def _setup_environment(self):
        """Handles filesystem and logging setup."""
        if self.args.models:
            self.args.model_paths = [p.strip() for p in self.args.models.split(',')]
        elif self.args.model:
            self.args.model_paths = self.args.model
        else:
            if self.args.raw_args_template and '{MODEL_PATHS}' in self.args.raw_args_template:
                raise ValueError("Raw args template contains '{MODEL_PATHS}' but no models were provided.")
            if not self.args.raw_args_template:
                raise ValueError("No model files provided.")
            self.args.model_paths = []

        temp_dir_base = "/dev/shm" if os.path.exists("/dev/shm") else None
        self.workdir = tempfile.mkdtemp(prefix=f"{self.args.attack_type}_host_attack_", dir=temp_dir_base)
        if temp_dir_base:
            print(f"--- Optimization: Using in-memory temp directory: {self.workdir} ---")
        
        os.makedirs(self.args.output_dir, exist_ok=True)
        
        # --- Setup Logging ---
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        params_to_exclude = {'executable', 'image', 'hooks', 'model', 'models', 'output_dir', 'workers'}
        args_dict = vars(self.args)
        param_str = "_".join([f"{key}-{val}" for key, val in sorted(args_dict.items()) if key not in params_to_exclude and val is not None and val is not False])
        param_str = re.sub(r'[^a-zA-Z0-9_\-.]', '_', param_str)
        log_filename = f"{timestamp}_{self.args.attack_type}_{param_str[:100]}.csv"
        detailed_log_path = os.path.join(self.args.output_dir, log_filename)
        
        self.detailed_log_file = open(detailed_log_path, 'w')
        params_json = json.dumps(args_dict, indent=4, default=str)
        self.detailed_log_file.write("# --- Attack Parameters ---\n")
        for line in params_json.splitlines():
            self.detailed_log_file.write(f"# {line}\n")
        self.detailed_log_file.write("# -----------------------\n\n")

        log_header = ["iteration", "total_queries", "loss", "best_loss", "lr", "is_successful_iter", "num_satisfied_hooks", "total_hooks", "attack_mode", "focus_targets", "hook_details", "iter_time_s", "total_time_s"]
        self.detailed_log_file.write(",".join(log_header) + "\n")
        print(f"--- Detailed metrics will be logged to: {detailed_log_path} ---")

    def _load_resources(self):
        """Loads the image and hook configuration."""
        print("--- Preparing environment: Verifying local paths ---")
        if self.args.raw_args_template:
            executable_path = shlex.split(self.args.raw_args_template)[0]
            static_files = [executable_path, self.args.hooks] + self.args.model_paths
            if not os.path.isabs(executable_path):
                 print(f"--- Warning: Executable path '{executable_path}' in raw template is not absolute. ---")
        else:
            static_files = [self.args.executable, self.args.hooks] + self.args.model_paths
        
        gdb_script_path = os.path.join(os.path.dirname(__file__), "gdb_script_host.py")
        static_files.append(gdb_script_path)
        
        for f in static_files:
            if not os.path.exists(f):
                raise FileNotFoundError(f"Required file not found: {f}")

        print("--- Loading hook configuration from JSON ---")
        with open(self.args.hooks, 'r') as f:
            self.hook_config = json.load(f)
        if not self.hook_config:
            raise ValueError("Hook configuration file is empty or invalid.")
        print(f"--- Loaded {len(self.hook_config)} hook configurations. ---")

        # --- Setup Dynamic Focus State ---
        if self.args.enable_dynamic_focus:
            print("\n--- Dynamic Focus Strategy ENABLED ---")
            for hook_info in self.hook_config:
                address = hook_info.get("address")
                if not address: continue
                self.hooks_attack_state[address] = {"original_weight": float(hook_info.get("weight", 1.0)), "dynamic_weight": self.args.non_target_weight, "loss_history": [], "descent_rate": 0.0, "consecutive_satisfaction_count": 0}
            print(f"Initial mode: Scouting. All hooks set to base weight: {self.args.non_target_weight}")
        else:
            print("\n--- Static Weight Strategy ENABLED ---")
            for hook_info in self.hook_config:
                address = hook_info.get("address")
                if not address: continue
                self.hooks_attack_state[address] = {"dynamic_weight": float(hook_info.get("weight", 1.0))}

        # --- Load and Prepare Image ---
        original_image = cv2.imread(self.args.image, cv2.IMREAD_COLOR)
        if original_image is None:
            raise FileNotFoundError(f"Could not read original image: {self.args.image}")
        if original_image.ndim == 2:
            original_image = cv2.cvtColor(original_image, cv2.COLOR_GRAY2BGR)
        
        self.attack_image = cv2.cvtColor(original_image, cv2.COLOR_BGR2RGB).astype(np.float32)
        self.original_image_float = self.attack_image.copy()

    def _update_learning_rate(self, iteration):
        if not hasattr(self.args, 'enable_stagnation_decay'): return

        decay_reason = None
        if self.args.enable_stagnation_decay:
            if (iteration - self.iteration_of_last_decay) >= self.args.lr_decay_steps:
                decay_reason = f"SCHEDULED ({self.args.lr_decay_steps} steps passed)"
            elif self.stagnation_patience_counter >= self.args.stagnation_patience:
                decay_reason = f"STAGNATION ({self.args.stagnation_patience} stagnant iterations)"

            if decay_reason:
                self.total_decay_count += 1
                self.iteration_of_last_decay = iteration
                self.stagnation_patience_counter = 0
                self.current_lr = self.args.learning_rate * (self.args.lr_decay_rate ** self.total_decay_count)
                print(f"Decaying LR due to {decay_reason}. New LR: {self.current_lr:.6f}")

    def _evaluate_image(self, image_to_eval):
        """Encodes, runs, and evaluates a single image, returning all results."""
        image_uint8_bgr = cv2.cvtColor(image_to_eval.astype(np.uint8), cv2.COLOR_RGB2BGR)
        is_success_encoding, encoded_image = cv2.imencode(".png", image_uint8_bgr)
        
        if not is_success_encoding:
            print("Warning: Failed to encode attack image for verification.")
            return False, {}, {}, float('inf'), {}

        is_successful, current_hooks, hooked_errors = self._run_attack_iteration(encoded_image.tobytes(), "temp_eval_image.png")
        
        dynamic_weights = {addr: state["dynamic_weight"] for addr, state in self.hooks_attack_state.items()}
        loss, hook_diagnostics = _calculate_targetless_loss(current_hooks, self.hook_config, dynamic_weights, self.args.satisfaction_threshold, margin=self.args.margin, missing_hook_penalty=self.args.missing_hook_penalty)
        
        return is_successful, current_hooks, hooked_errors, loss, hook_diagnostics

    def _log_iteration_details(self, iteration, loss, is_successful, hook_diagnostics, iter_time, total_time):
        num_satisfied = sum(1 for d in hook_diagnostics.values() if d.get("is_satisfied", False))
        
        hook_details_str = ""
        if is_successful or (iteration == self.args.iterations - 1):
            details = {addr: {"loss": round(float(diag.get("individual_loss", 0.0)), 6), "satisfied": bool(diag.get("is_satisfied", False))} for addr, diag in hook_diagnostics.items()}
            hook_details_str = json.dumps(details)

        targets_str = "N/A"
        if self.args.enable_dynamic_focus:
            if isinstance(self.current_focus_target, list):
                targets_str = ";".join(self.current_focus_target) if self.current_focus_target else "None"
            elif self.current_focus_target:
                targets_str = self.current_focus_target
            else:
                targets_str = "None"

        log_data = [iteration + 1, self.total_queries, f"{loss:.6f}", f"{self.best_loss_so_far:.6f}", f"{self.current_lr:.6f}", is_successful, num_satisfied, len(self.hook_config), self.attack_mode, f'"{targets_str}"', f'"{hook_details_str}"', f"{iter_time:.2f}", f"{total_time:.2f}"]
        self.detailed_log_file.write(",".join(map(str, log_data)) + "\n")
        self.detailed_log_file.flush()

    def _save_images(self, current_loss):
        attack_image_bgr = cv2.cvtColor(self.attack_image.astype(np.uint8), cv2.COLOR_RGB2BGR)
        cv2.imwrite(os.path.join(self.args.output_dir, f"latest_attack_image_{self.args.attack_type}.png"), attack_image_bgr)

        if current_loss < self.best_loss_so_far:
            self.best_loss_so_far = current_loss
            print(f"New best loss found: {current_loss:.6f}. Saving best image.")
            self.best_image_path = os.path.join(self.args.output_dir, f"best_attack_image_{self.args.attack_type}.png")
            cv2.imwrite(self.best_image_path, attack_image_bgr)

    def _update_stagnation_counter(self, loss):
        if loss < self.best_loss_for_stagnation - self.args.min_loss_delta:
            self.best_loss_for_stagnation = loss
            self.stagnation_patience_counter = 0
        else:
            self.stagnation_patience_counter += 1
        print(f"Stagnation patience: {self.stagnation_patience_counter}/{self.args.stagnation_patience}")

    def _update_dynamic_focus(self, hook_diagnostics):
        if self.attack_mode == "scouting":
            self.scouting_cycle_counter += 1
            print(f"Scouting... Cycle {self.scouting_cycle_counter}/{self.args.evaluation_window}")

            for addr, state in self.hooks_attack_state.items():
                if addr in hook_diagnostics:
                    state["loss_history"].append(hook_diagnostics[addr]["individual_loss"])

            if self.scouting_cycle_counter >= self.args.evaluation_window:
                print(f"\n--- End of Scouting Window. Analyzing results... ---")
                
                for addr, state in self.hooks_attack_state.items():
                    if len(state["loss_history"]) > 1:
                        indices = np.arange(len(state["loss_history"]))
                        slope, _, _, _, _ = stats.linregress(indices, state["loss_history"])
                        state["descent_rate"] = -slope
                    else:
                        state["descent_rate"] = 0.0
                
                progressing_targets = [addr for addr, state in self.hooks_attack_state.items() if addr in hook_diagnostics and not hook_diagnostics[addr]["is_satisfied"] and state["descent_rate"] > self.args.min_loss_delta]
                
                self.scouting_cycle_counter = 0
                for state in self.hooks_attack_state.values():
                    state["loss_history"] = []

                if progressing_targets:
                    self.current_focus_target = progressing_targets
                    self.attack_mode = "focused_fire"
                    print(f"FOCUS SHIFT: New targets are '{', '.join(self.current_focus_target)}'.")
                    
                    print("--- Updating hook weights for FOCUSED_FIRE mode ---")
                    for addr, state in self.hooks_attack_state.items():
                        state["consecutive_satisfaction_count"] = 0
                        is_satisfied = hook_diagnostics.get(addr, {}).get("is_satisfied", False)
                        if addr in self.current_focus_target:
                            state["dynamic_weight"] = self.args.boost_weight
                        elif is_satisfied:
                            state["dynamic_weight"] = self.args.satisfied_weight
                        else:
                            state["dynamic_weight"] = self.args.non_target_weight
                    
                    if self.args.enable_stagnation_decay:
                        self.stagnation_patience_counter = 0
                        self.best_loss_for_stagnation = float('inf')
                else:
                    print("No hooks showed significant progress. Remaining in SCOUTING mode.")
        
        elif self.attack_mode == "focused_fire":
            if not self.current_focus_target or not isinstance(self.current_focus_target, list):
                self.attack_mode = "scouting"
                print("No focus targets found, switching back to SCOUTING.")
                return

            still_active_targets = []
            for target in self.current_focus_target:
                is_satisfied = hook_diagnostics.get(target, {}).get("is_satisfied", False)
                
                if is_satisfied:
                    self.hooks_attack_state[target]["consecutive_satisfaction_count"] += 1
                else:
                    self.hooks_attack_state[target]["consecutive_satisfaction_count"] = 0

                if self.hooks_attack_state[target]["consecutive_satisfaction_count"] >= self.args.satisfaction_patience:
                    print(f"  - Target {target}: RETIRED. Assigning satisfied maintenance weight.")
                    self.hooks_attack_state[target]["dynamic_weight"] = self.args.satisfied_weight
                else:
                    still_active_targets.append(target)
                    self.hooks_attack_state[target]["dynamic_weight"] = self.args.boost_weight
            
            self.current_focus_target = still_active_targets

            if not self.current_focus_target:
                print(f"\n--- ALL TARGETS RETIRED! Switching back to SCOUTING mode. ---")
                self.attack_mode = "scouting"
                self.current_focus_target = None
                self.scouting_cycle_counter = 0
                if self.args.enable_stagnation_decay:
                    self.stagnation_patience_counter = 0
                    self.best_loss_for_stagnation = float('inf')
                
                for addr, state in self.hooks_attack_state.items():
                    is_satisfied = hook_diagnostics.get(addr, {}).get("is_satisfied", False)
                    state["dynamic_weight"] = self.args.satisfied_weight if is_satisfied else self.args.non_target_weight
                    state["loss_history"] = []
                    state["descent_rate"] = 0.0
                    state["consecutive_satisfaction_count"] = 0

    def _handle_success(self):
        """Performs final verification and logging upon successful attack."""
        print("\nAttack successful according to GDB hooks!")
        successful_image_path = os.path.join(self.args.output_dir, f"successful_attack_image_{self.args.attack_type}.png")
        cv2.imwrite(successful_image_path, cv2.cvtColor(self.attack_image.astype(np.uint8), cv2.COLOR_RGB2BGR))
        print(f"Adversarial image saved to: {successful_image_path}")
        
        print("\n--- Verifying final image by direct execution (without GDB) ---")
        final_output = self._get_executable_output(successful_image_path)
        print("Execution Output on Successful Image:")
        print(final_output)

        if "true" in final_output.lower():
            print("--- Verification PASSED: Direct execution confirms success. ---")
        else:
            print("--- Verification FAILED: Direct execution does not confirm success. ---")

        _, final_hooks, _ = self._run_executable_and_parse_hooks(successful_image_path)
        print("GDB Hook Info on Successful Image (JSON):")
        print(json.dumps(final_hooks, indent=4))
    
    def _cleanup(self):
        """Cleans up temporary files and closes log files."""
        if self.detailed_log_file:
            self.detailed_log_file.close()
        if self.workdir and os.path.exists(self.workdir):
            shutil.rmtree(self.workdir)
            print(f"Temporary directory {self.workdir} cleaned up.")
        print("Cleanup finished.")

    def _run_attack_iteration(self, image_content, image_name_on_host):
        image_path_on_host = os.path.join(self.workdir, image_name_on_host)

        with open(image_path_on_host, 'wb') as f:
            f.write(image_content)

        is_successful, hooked_values, hooked_errors = self._run_executable_and_parse_hooks(image_path_on_host, self.args, self.args.model_paths)

        os.remove(image_path_on_host)
        
        return is_successful, hooked_values, hooked_errors

    def _get_executable_output(self, image_path_on_host):
        if self.args.raw_args_template:
            model_paths_str = ' '.join([os.path.abspath(p) for p in self.args.model_paths])
            command_template = self.args.raw_args_template.replace('{MODEL_PATHS}', model_paths_str)
            command_template = command_template.replace('{IMAGE_PATH}', os.path.abspath(image_path_on_host))
            
            command = shlex.split(command_template)
            command[0] = os.path.abspath(command[0])
        else:
            command = [os.path.abspath(self.args.executable), *[os.path.abspath(p) for p in self.args.model_paths], os.path.abspath(image_path_on_host)]

        script_dir = os.path.dirname(__file__)
        project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
        mnn_lib_path = os.path.join(project_root, 'third_party', 'mnn', 'lib')
        onnx_lib_path = os.path.join(project_root, 'third_party', 'onnxruntime', 'lib')
        inspire_lib_path = os.path.join(project_root, 'third_party', 'InspireFace', 'lib')
        
        env = os.environ.copy()
        existing_ld_path = env.get('LD_LIBRARY_PATH', '')
        env['LD_LIBRARY_PATH'] = f"{mnn_lib_path}:{onnx_lib_path}:{inspire_lib_path}:{existing_ld_path}"

        try:
            result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30, env=env)
            return result.stdout + "\n" + result.stderr
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            stderr = e.stderr if hasattr(e, 'stderr') else "Timeout or error"
            return f"Error running host executable for '{image_path_on_host}': {stderr}"

    def _run_executable_and_parse_hooks(self, image_path_on_host):
        return _run_executable_and_parse_hooks(image_path_on_host, self.args, self.args.model_paths)
    
    def _write_multiple_files_to_host(self, files_data, dest_dir):
        for filename, data in files_data:
            with open(os.path.join(dest_dir, filename), 'wb') as f:
                f.write(data)

    def _remove_files_on_host_batch(self, file_pattern):
        try:
            for f in glob.glob(file_pattern):
                os.remove(f)
        except OSError as e:
            print(f"Warning: Error during batch remove: {e}")
