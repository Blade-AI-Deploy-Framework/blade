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
import shutil
import tempfile
import time
import shlex
import frida
import threading
from collections import deque
from scipy import stats
from concurrent.futures import ThreadPoolExecutor

# --- Path Setup ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))

# ==============================================================================
#  AttackWorker Class: Encapsulates a single parallel attack instance
# ==============================================================================

class AttackWorker:
    """
    Manages all resources for a single, parallel instance of an attack environment,
    including the target process, Frida session, and GDB debugger connection.
    """
    def __init__(self, worker_id, device, gdb_port_base, hook_config, base_symbol, gdb_client_path):
        self.worker_id = worker_id
        self.device = device
        self.gdb_port = gdb_port_base + worker_id
        self.hook_config = hook_config
        self.hook_json_str = json.dumps(hook_config)
        self.base_symbol = base_symbol
        self.gdb_client_path = os.path.expanduser(gdb_client_path)

        # Resources to be initialized
        self.pid = None
        self.session = None
        self.script = None
        self.gdbserver_proc = None
        self.gdb_client_proc = None

        # State and communication
        self.is_ready = threading.Event()
        self.evaluation_complete = threading.Event()
        self.attack_success = threading.Event()
        self.gdb_output = []
        self.frida_payload = None
        self.lock = threading.Lock()

    def _on_message(self, message, data):
        """Callback for messages from this worker's Frida agent."""
        if message.get('type') == 'send' and 'payload' in message:
            payload = message.get('payload')
            with self.lock:
                self.frida_payload = payload

            if isinstance(payload, dict) and payload.get('type') == 'status' and payload.get('payload') == 'Verification complete':
                self.evaluation_complete.set()
                if payload.get('result') == 0 or payload.get('result') == 4108:
                    self.attack_success.set()

    def initialize(self, process_name):
        """Initializes all resources for this worker: Frida, GDB server, and GDB client."""
        try:
            # Stagger the start to avoid overwhelming the device's adb/su with parallel requests
            time.sleep(self.worker_id * 0.5)

            print(f"[Worker-{self.worker_id}] Initializing...")
            # 1. Initialize Frida
            self.pid = self.device.spawn([process_name])
            self.session = self.device.attach(self.pid)
            
            js_code_path = os.path.join(PROJECT_ROOT, 'frida-tool', 'core_logic.js')
            with open(js_code_path, 'r') as f:
                js_code = f.read()
                
            self.script = self.session.create_script(js_code)
            self.script.on('message', self._on_message)
            self.script.load()
            self.device.resume(self.pid)
            print(f"[Worker-{self.worker_id}] Process spawned with PID: {self.pid}")

            # 2. Start GDB Server
            subprocess.run(f"adb forward --remove tcp:{self.gdb_port}", shell=True, check=False, capture_output=True)
            gdbserver_path = "/data/local/tmp/gdbserver"
            gdbserver_command = f"adb shell \"su -c '{gdbserver_path} :{self.gdb_port} --attach {self.pid}'\""
            self.gdbserver_proc = subprocess.Popen(gdbserver_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            gdbserver_ready_event = threading.Event()
            gdbserver_output_capture = []
            def gdbserver_reader():
                if self.gdbserver_proc.stdout:
                    for line in iter(self.gdbserver_proc.stdout.readline, ''):
                        stripped_line = line.strip()
                        gdbserver_output_capture.append(stripped_line)
                        if f"Listening on port {self.gdb_port}" in stripped_line or "Attached; pid" in stripped_line:
                            gdbserver_ready_event.set()
                    self.gdbserver_proc.stdout.close()
            
            threading.Thread(target=gdbserver_reader, daemon=True).start()
            if not gdbserver_ready_event.wait(timeout=20):
                print(f"\n--- [Worker-{self.worker_id}] GDB Server output on failure ---")
                for line in gdbserver_output_capture:
                    print(f"  [GDBServer-{self.worker_id}] {line}")
                print(f"--- End of GDB Server output for Worker-{self.worker_id} ---\n")
                raise RuntimeError(f"gdbserver for worker {self.worker_id} did not signal ready.")
            
            subprocess.run(f"adb forward tcp:{self.gdb_port} tcp:{self.gdb_port}", shell=True, check=True)
            print(f"[Worker-{self.worker_id}] GDB server is running and port {self.gdb_port} is forwarded.")

            # 3. Prepare and run GDB client
            template_path = os.path.join(PROJECT_ROOT, 'frida_gdb_orchestrator', 'gdb_attach_template.py')
            with open(template_path, 'r') as f:
                template = f.read()
            gdb_script_content = template.replace("PLACEHOLDER_PORT", str(self.gdb_port))
            escaped_json = self.hook_json_str.replace('\\', '\\\\').replace('"', '\\"')
            gdb_script_content = gdb_script_content.replace("PLACEHOLDER_HOOK_CONFIG_JSON_STR", escaped_json)
            gdb_script_content = gdb_script_content.replace("PLACEHOLDER_BASE_ADDRESS_SYMBOL", self.base_symbol)
            
            script_path = f"/tmp/gdb_attach_script_{self.worker_id}.py"
            with open(script_path, 'w') as f:
                f.write(gdb_script_content)

            command = [self.gdb_client_path, "-batch", "-x", script_path]
            self.gdb_client_proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            def gdb_client_reader():
                if self.gdb_client_proc.stdout:
                    for line in iter(self.gdb_client_proc.stdout.readline, ''):
                        with self.lock:
                            self.gdb_output.append(line)
                        if "[GDB SCRIPT READY]" in line.strip():
                            self.is_ready.set()
                    self.gdb_client_proc.stdout.close()
            
            threading.Thread(target=gdb_client_reader, daemon=True).start()
            if not self.is_ready.wait(timeout=30):
                raise RuntimeError(f"GDB client for worker {self.worker_id} did not signal ready.")
            
            print(f"[Worker-{self.worker_id}] Initialization COMPLETE.")
            return self

        except Exception as e:
            print(f"[Worker-{self.worker_id}] FAILED to initialize: {e}")
            self.cleanup()
            raise

    def cleanup(self):
        """Cleans up all resources used by this worker."""
        print(f"[Worker-{self.worker_id}] Cleaning up...")
        if self.session:
            try: self.session.detach()
            except frida.InvalidOperationError: pass
        if self.gdb_client_proc and self.gdb_client_proc.poll() is None:
            self.gdb_client_proc.terminate()
        if self.gdbserver_proc and self.gdbserver_proc.poll() is None:
            self.gdbserver_proc.terminate()
        subprocess.run(f"adb forward --remove tcp:{self.gdb_port}", shell=True, check=False, capture_output=True)
        print(f"[Worker-{self.worker_id}] Cleanup complete.")

    def evaluate_image(self, image_np, args, dynamic_weights):
        """Evaluates a single image mutation using this worker's dedicated resources."""
        with self.lock:
            self.gdb_output.clear()
            self.evaluation_complete.clear()
            self.attack_success.clear()
            self.frida_payload = None

            if self.script is None:
                print(f"[Worker-{self.worker_id}] Error: Frida script is not loaded.")
                return float('inf'), {}, False, None

            # Send image via Frida
            image_bgr = cv2.cvtColor(image_np.astype(np.uint8), cv2.COLOR_RGB2BGR)
            image_resized = cv2.resize(image_bgr, (480, 640))
            yuv_image = cv2.cvtColor(image_resized, cv2.COLOR_BGR2YUV)
            y = yuv_image[:, :, 0]
            u = yuv_image[:, :, 1][::2, ::2]
            v = yuv_image[:, :, 2][::2, ::2]
            data = np.rot90(y, -1).flatten().tobytes() + u.flatten().tobytes() + v.flatten().tobytes()
            self.script.post({'type': 'image_bytes'}, data)

        # Wait for evaluation to finish
        completed = self.evaluation_complete.wait(timeout=10)
        if not completed:
            print(f"[Worker-{self.worker_id}] Evaluation timed out.")
            return float('inf'), {}, False, None

        time.sleep(0.2)  # Allow GDB output to be fully captured
        with self.lock:
            gdb_output_copy = list(self.gdb_output)
            frida_payload_copy = self.frida_payload
            is_successful = self.attack_success.is_set()

        # Parse results
        current_hooks = parse_gdb_output_from_list(gdb_output_copy)

        if args.verbose_gdb:
            print(f"\n--- [Worker-{self.worker_id}] GDB Raw Output ---")
            for line in gdb_output_copy:
                print(line, end='')
            print(f"--- [Worker-{self.worker_id}] Parsed Hooks ---")
            print(json.dumps(current_hooks, indent=2))
            print("------------------------------------------\n")

        loss, hook_diagnostics = calculate_targetless_loss(
            current_hooks, self.hook_config, dynamic_weights, args.satisfaction_threshold,
            margin=args.margin, missing_hook_penalty=args.missing_hook_penalty,
            verbose=False, # Verbosity should be handled outside the worker
            args=args
        )
        return loss, hook_diagnostics, is_successful, frida_payload_copy

# ==============================================================================
#  Standalone Helper Functions (Loss, GDB Parsing, etc.)
# ==============================================================================

def parse_gdb_output_from_list(gdb_output_lines):
    # ... (This function is unchanged)
    hooked_values = {}
    for line in gdb_output_lines:
        if "HOOK_RESULT" in line:
            match = re.search(r'offset=(0x[0-9a-fA-F]+)\s+.*value=(.*)', line)
            if not match: continue
            offset, val_str = match.groups()
            val_str = val_str.strip()
            try:
                value = None
                if val_str.startswith('{'):
                    float_match = re.search(r'f\s*=\s*([-\d.e+]+)', val_str)
                    if float_match: value = float(float_match.group(1))
                else:
                    value = float(val_str)
                
                if value is not None:
                    if offset not in hooked_values: hooked_values[offset] = []
                    hooked_values[offset].append(value)
                else:
                    print(f"[GDB Parser Debug] Could not parse float from value string: '{val_str}'")
            except (ValueError, TypeError):
                 print(f"[GDB Parser Debug] Exception while parsing value string: '{val_str}'")
                 pass
    return hooked_values

def calculate_targetless_loss(current_hooks, hook_config, dynamic_weights, satisfaction_threshold, margin=0.01, missing_hook_penalty=10.0, verbose=False, args=None):
    # ... (This function is unchanged)
    if not isinstance(current_hooks, dict):
        return len(hook_config) * missing_hook_penalty if hook_config else float('inf'), {}

    total_loss = 0.0
    hook_diagnostics = {}
    for hook_info in hook_config:
        address = hook_info.get("address")
        branch_instruction = hook_info.get("original_branch_instruction")
        if not all([address, branch_instruction]): continue
        dynamic_weight = dynamic_weights.get(address, 1.0)
        values = current_hooks.get(address)
        hook_loss_sum = 0.0
        formulas_for_hook = []
        values_for_hook = []

        if "pairs_to_process" in hook_info:
            pairs_config = hook_info["pairs_to_process"]
            if values is None:
                hook_loss_sum = missing_hook_penalty * len(pairs_config)
            else:
                for pair_cfg in pairs_config:
                    pair_loss, formula, v1, v2 = _calculate_loss_for_one_pair(values, pair_cfg["pair_index"], pair_cfg.get("attack_mode", "satisfy"), branch_instruction, margin, missing_hook_penalty, args)
                    hook_loss_sum += pair_loss
                    formulas_for_hook.append(f"Pair {pair_cfg['pair_index']} ({pair_cfg.get('attack_mode', 'satisfy')}): {formula} -> Loss: {pair_loss:.6f}")
                    if v1 is not None and v2 is not None:
                        values_for_hook.append({"pair": pair_cfg["pair_index"], "v1": v1, "v2": v2})
        else:
            pair_indices = hook_info.get("value_pairs", [1])
            attack_mode = hook_info.get("attack_mode", "satisfy")
            if values is None:
                hook_loss_sum = missing_hook_penalty * len(pair_indices)
            else:
                for pair_index in pair_indices:
                    pair_loss, formula, v1, v2 = _calculate_loss_for_one_pair(values, pair_index, attack_mode, branch_instruction, margin, missing_hook_penalty, args)
                    hook_loss_sum += pair_loss
                    formulas_for_hook.append(f"Pair {pair_index} ({attack_mode}): {formula} -> Loss: {pair_loss:.6f}")
                    if v1 is not None and v2 is not None:
                        values_for_hook.append({"pair": pair_index, "v1": v1, "v2": v2})

        total_loss += hook_loss_sum * dynamic_weight
        is_satisfied = hook_loss_sum < satisfaction_threshold
        hook_diagnostics[address] = {
            "individual_loss": hook_loss_sum, "is_satisfied": is_satisfied,
            "weight": dynamic_weight, "formulas": formulas_for_hook,
            "values": values_for_hook
        }

    if verbose:
        # Verbose printing logic can be added here if needed, based on the main function's needs
        pass

    return total_loss, hook_diagnostics

def _calculate_loss_for_one_pair(values, pair_index, attack_mode, branch_instruction, margin, missing_hook_penalty, args=None):
    idx1, idx2 = (pair_index - 1) * 2, (pair_index - 1) * 2 + 1
    if len(values) <= idx2:
        return missing_hook_penalty, f"Pair #{pair_index} values missing", None, None

    v1, v2 = values[idx1], values[idx2]
    pair_loss, formula = 0.0, "N/A"
    
    sharpness = args.loss_sharpness if args and hasattr(args, 'loss_sharpness') else 1.0

    # Invert logic - Full implementation from spsa_attack_android.py
    if attack_mode == 'invert':
        if branch_instruction in ["b.gt", "b.hi", "b.ge", "b.hs", "b.cs", "b.pl"]:
            # Original Hinge Loss (commented out)
            pair_loss = np.maximum(0, (v1 - v2) + margin)
            formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})"
            # Original Softplus Loss (commented out)
            # x = sharpness * ((v1 - v2) + margin)
            # pair_loss = (1 / sharpness) * np.log(1 + np.exp(x))
            # formula = f"softplus({v1:.4f} - {v2:.4f} + {margin}, beta={sharpness})"
            # New Quadratic Hinge Loss
            # pair_loss = np.maximum(0, (v1 - v2) + margin) ** 2
            # formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})^2"
        elif branch_instruction in ["b.lt", "b.lo", "b.cc", "b.mi", "b.le", "b.ls"]:
            # Original Hinge Loss (commented out)
            pair_loss = np.maximum(0, (v2 - v1) + margin)
            formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})"
            # Original Softplus Loss (commented out)
            # x = sharpness * ((v2 - v1) + margin)
            # pair_loss = (1 / sharpness) * np.log(1 + np.exp(x))
            # formula = f"softplus({v2:.4f} - {v1:.4f} + {margin}, beta={sharpness})"
            # New Quadratic Hinge Loss
            # pair_loss = np.maximum(0, (v2 - v1) + margin) ** 2
            # formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})^2"
        elif branch_instruction == "b.eq":
            # Original Hinge Loss (commented out)
            pair_loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
            formula = f"max(0, {margin} - abs({v1:.4f} - {v2:.4f}))^2"
            # New Softplus Loss
            # x = sharpness * (margin - np.abs(v1 - v2))
            # pair_loss = (1 / sharpness) * np.log(1 + np.exp(x))
            # formula = f"softplus({margin} - abs({v1:.4f} - {v2:.4f}), beta={sharpness})"
        elif branch_instruction == "b.ne": 
            pair_loss = (v1 - v2) ** 2
            formula = f"({v1:.4f} - {v2:.4f})^2"
    # Satisfy logic - Full implementation from spsa_attack_android.py
    else:
        if branch_instruction in ["b.gt", "b.hi", "b.ge", "b.hs", "b.cs", "b.pl"]:
            # Original Hinge Loss (commented out)
            pair_loss = np.maximum(0, (v2 - v1) + margin)
            formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})"
            # Original Softplus Loss (commented out)
            # x = sharpness * ((v2 - v1) + margin)
            # pair_loss = (1 / sharpness) * np.log(1 + np.exp(x))
            # formula = f"softplus({v2:.4f} - {v1:.4f} + {margin}, beta={sharpness})"
            # New Quadratic Hinge Loss
            # pair_loss = np.maximum(0, (v2 - v1) + margin) ** 2
            # formula = f"max(0, {v2:.4f} - {v1:.4f} + {margin})^2"
        elif branch_instruction in ["b.lt", "b.lo", "b.cc", "b.mi", "b.le", "b.ls"]:
            # Original Hinge Loss (commented out)
            pair_loss = np.maximum(0, (v1 - v2) + margin)
            formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})"
            # Original Softplus Loss (commented out)
            # x = sharpness * ((v1 - v2) + margin)
            # pair_loss = (1 / sharpness) * np.log(1 + np.exp(x))
            # formula = f"softplus({v1:.4f} - {v2:.4f} + {margin}, beta={sharpness})"
            # New Quadratic Hinge Loss
            # pair_loss = np.maximum(0, (v1 - v2) + margin) ** 2
            # formula = f"max(0, {v1:.4f} - {v2:.4f} + {margin})^2"
        elif branch_instruction == "b.eq": 
            pair_loss = (v1 - v2) ** 2
            formula = f"({v1:.4f} - {v2:.4f})^2"
        elif branch_instruction == "b.ne":
            # Original Hinge Loss (commented out)
            pair_loss = np.maximum(0, margin - np.abs(v1 - v2)) ** 2
            formula = f"max(0, {margin} - abs({v1:.4f} - {v2:.4f}))^2"
            # New Softplus Loss
            # x = sharpness * (margin - np.abs(v1 - v2))
            # pair_loss = (1 / sharpness) * np.log(1 + np.exp(x))
            # formula = f"softplus({margin} - abs({v1:.4f} - {v2:.4f}), beta={sharpness})"

    return pair_loss, formula, v1, v2

# ==============================================================================
#  Parallel Gradient Estimation
# ==============================================================================

def _evaluate_spsa_sample_on_worker(task_args):
    """Function executed by each thread in the pool to evaluate one SPSA sample."""
    worker, image, delta, current_c, args, dynamic_weights = task_args
    
    if args.attack_y_channel_only:
        # Convert RGB to YUV, apply delta to Y channel, and convert back.
        yuv_image = cv2.cvtColor(image.astype(np.uint8), cv2.COLOR_RGB2YUV).astype(np.float32)
        y_channel = yuv_image[:, :, 0]
        
        # delta has shape (H, W, 1), so we squeeze it to (H, W) for channel-wise math
        delta_squeezed = np.squeeze(delta, axis=-1)
        
        # Apply perturbation to the Y channel
        y_pos = y_channel + current_c * delta_squeezed
        y_neg = y_channel - current_c * delta_squeezed
        
        # Reconstruct positive mutant
        yuv_pos = yuv_image.copy()
        yuv_pos[:, :, 0] = y_pos
        mutant_pos = cv2.cvtColor(np.clip(yuv_pos, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB).astype(np.float32)

        # Reconstruct negative mutant
        yuv_neg = yuv_image.copy()
        yuv_neg[:, :, 0] = y_neg
        mutant_neg = cv2.cvtColor(np.clip(yuv_neg, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB).astype(np.float32)
    else:
        mutant_pos = np.clip(image + current_c * delta, 0, 255)
        mutant_neg = np.clip(image - current_c * delta, 0, 255)

    loss_pos, _, _, _ = worker.evaluate_image(mutant_pos, args, dynamic_weights)
    loss_neg, _, _, _ = worker.evaluate_image(mutant_neg, args, dynamic_weights)

    if np.isinf(loss_pos) or np.isinf(loss_neg):
        print(f"[Worker-{worker.worker_id}] Warning: Infinite loss detected. Discarding gradient sample.")
        # Return a zero gradient of the correct shape
        if args.attack_y_channel_only:
            return np.zeros((image.shape[0], image.shape[1], 1), dtype=np.float32)
        else:
            return np.zeros_like(image, dtype=np.float32)

    grad_sample = delta * ((loss_pos - loss_neg) / (2 * current_c + 1e-10))
    return grad_sample

def estimate_gradient_spsa_parallel(workers, image, args, current_c, dynamic_weights):
    """
    Estimates the gradient using SPSA by distributing evaluation tasks across multiple workers in parallel.
    """
    num_samples = args.spsa_grad_samples
    if num_samples <= 0: return np.zeros_like(image, dtype=np.float32)
    
    image_shape = image.shape
    deltas = []

    # Determine the shape for the delta perturbation based on the attack mode
    if args.attack_y_channel_only:
        pert_shape = (image_shape[0], image_shape[1]) # H, W for single channel
        resize_downsampled_shape_base = (args.resize_dim, args.resize_dim) if args.resize_dim > 0 else None
    else:
        pert_shape = image_shape # H, W, C for three channels
        resize_downsampled_shape_base = (args.resize_dim, args.resize_dim, image_shape[2]) if args.resize_dim > 0 else None

    for _ in range(num_samples):
        if args.resize_dim and args.resize_dim > 0:
            delta_low_dim = np.random.choice([-1, 1], size=resize_downsampled_shape_base).astype(np.float32)
            delta = cv2.resize(delta_low_dim, (image_shape[1], image_shape[0]), interpolation=cv2.INTER_NEAREST)
        else:
            delta = np.random.choice([-1, 1], size=pert_shape).astype(np.float32)
        
        # Ensure delta is always 3D (e.g., H, W, 1) for broadcasting
        if delta.ndim == 2:
            delta = np.expand_dims(delta, axis=-1)
            
        deltas.append(delta)

    tasks = []
    for i in range(num_samples):
        # Assign tasks to workers in a round-robin fashion
        worker = workers[i % len(workers)]
        tasks.append((worker, image, deltas[i], current_c, args, dynamic_weights))

    print(f"--- Estimating gradient with {num_samples} SPSA samples across {len(workers)} workers ---")
    
    if args.attack_y_channel_only:
        grad_shape = (image.shape[0], image.shape[1], 1)
        total_grads = np.zeros(grad_shape, dtype=np.float32)
    else:
        total_grads = np.zeros_like(image, dtype=np.float32)
        
    with ThreadPoolExecutor(max_workers=len(workers)) as executor:
        results = executor.map(_evaluate_spsa_sample_on_worker, tasks)
        for grad_sample in results:
            total_grads += grad_sample
            
    return total_grads / num_samples

# ==============================================================================
#  Main Attack Logic
# ==============================================================================

def main(args):
    workers = []
    detailed_log_file = None
    attack_image = None
    
    # --- 1. SETUP PHASE ---
    try:
        with open(args.hooks, 'r') as f:
            hook_config = json.load(f)
        
        print("[+] Initializing Frida to get device handle...")
        device = frida.get_usb_device()
        print(f"[+] Found USB device: {device}")

        # Create worker instances
        workers = [
            AttackWorker(i, device, args.gdb_port, hook_config, args.base_symbol, args.gdb_client)
            for i in range(args.num_workers)
        ]

        # Initialize workers in parallel
        print(f"--- Initializing {args.num_workers} workers in parallel... ---")
        with ThreadPoolExecutor(max_workers=args.num_workers) as executor:
            init_futures = [executor.submit(w.initialize, args.target_process) for w in workers]
            for future in init_futures:
                future.result() # Wait for each worker to complete and raise exceptions if any

        print("\n[+] All workers are ready. Starting SPSA attack.")

    except Exception as e:
        print(f"\n[ERROR] An error occurred during setup: {e}")
        # Cleanup will be handled in the finally block
        return

    start_time = time.time()
    total_queries = 0
    try:
        # --- Logging, Strategy, and Image Setup (similar to single-threaded version) ---
        os.makedirs(args.output_dir, exist_ok=True)
        
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        script_name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
        params_to_exclude = {'target_process', 'base_symbol', 'gdb_port', 'gdb_client', 'image', 'hooks', 'output_dir', 'num_workers'}
        args_dict = vars(args)
        param_str = "_".join([f"{key}-{val}" for key, val in sorted(args_dict.items()) if key not in params_to_exclude and val is not None and val is not False])
        param_str = re.sub(r'[^a-zA-Z0-9_\-.]', '_', param_str)
        log_filename = f"{timestamp}_{script_name}_{param_str[:100]}.csv"
        detailed_log_path = os.path.join(args.output_dir, log_filename)
        
        detailed_log_file = open(detailed_log_path, 'w')
        params_json = json.dumps(args_dict, indent=4, default=str)
        detailed_log_file.write("# --- Attack Parameters ---\n")
        for line in params_json.splitlines():
            detailed_log_file.write(f"# {line}\n")
        detailed_log_file.write("# -----------------------\n\n")

        log_header = ["iteration", "total_queries", "loss", "best_loss", "lr", "num_satisfied_hooks", "total_hooks", "attack_mode", "focus_targets", "hook_details", "iter_time_s", "total_time_s"]
        detailed_log_file.write(",".join(map(str, log_header)) + "\n")
        print(f"--- Detailed metrics will be logged to: {detailed_log_path} ---")

        original_image = cv2.cvtColor(cv2.imread(args.image), cv2.COLOR_BGR2RGB)
        attack_image = original_image.copy().astype(np.float32)
        original_image_float = original_image.copy().astype(np.float32)
        
        stagnation_patience_counter = 0
        iteration_of_last_decay = 0
        total_decay_count = 0
        best_loss_for_stagnation = float('inf')
        if args.enable_stagnation_decay:
            print("--- Stagnation-resetting decay enabled ---")

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
                hooks_attack_state[address] = { "dynamic_weight": float(hook_info.get("weight", 1.0)) }
        
        # --- Initial Loss Calculation (using worker 0) ---
        print("\n--- Calculating initial loss for original image ---")
        dynamic_weights = {addr: state["dynamic_weight"] for addr, state in hooks_attack_state.items()}
        initial_loss, _, is_successful_initial, initial_frida_payload = workers[0].evaluate_image(attack_image, args, dynamic_weights)
        total_queries += 1
        print(f"Initial loss: {initial_loss:.6f}")
        if initial_frida_payload:
            print(f"  Frida Agent Initial Output: result={initial_frida_payload.get('result')}, output='{initial_frida_payload.get('output')}'")

        if is_successful_initial:
            print("\nAttack successful on the original image (result=0)!")
            successful_image_path = os.path.join(args.output_dir, "successful_original_image.png")
            cv2.imwrite(successful_image_path, cv2.cvtColor(original_image, cv2.COLOR_RGB2BGR))
            print(f"Original image saved to: {successful_image_path}")
            return
        
        adam_step_counter = 0
        best_loss_so_far = float('inf')

        if args.attack_y_channel_only:
            pert_shape = (attack_image.shape[0], attack_image.shape[1], 1)
            m = np.zeros(pert_shape, dtype=np.float32)
            v = np.zeros(pert_shape, dtype=np.float32)
        else:
            m = np.zeros_like(attack_image, dtype=np.float32)
            v = np.zeros_like(attack_image, dtype=np.float32)
        
        # Initialize deque for gradient smoothing if enabled
        grad_history = None
        if args.grad_smoothing_samples > 1:
            grad_history = deque(maxlen=args.grad_smoothing_samples)
            print(f"--- Gradient smoothing enabled over {args.grad_smoothing_samples} samples ---")

        # --- 2. ATTACK LOOP PHASE ---
        for i in range(args.iterations):
            iter_start_time = time.time()
            print(f"\n--- Iteration {i+1}/{args.iterations} (Total Queries: {total_queries}) ---")

            # Check if any worker's GDB client has died
            for worker in workers:
                if worker.gdb_client_proc and worker.gdb_client_proc.poll() is not None:
                    print(f"[ERROR] GDB client for Worker-{worker.worker_id} has terminated. Aborting.")
                    raise RuntimeError("GDB client terminated unexpectedly.")

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
                 print(f"Decay triggered by {decay_reason}. New LR: {current_lr:.6f}")

            print(f"Current LR: {current_lr:.6f}, SPSA c: {current_c:.6f}")

            dynamic_weights = {addr: state["dynamic_weight"] for addr, state in hooks_attack_state.items()}
            grad_raw = estimate_gradient_spsa_parallel(workers, attack_image, args, current_c, dynamic_weights)
            total_queries += 2 * args.spsa_grad_samples
            
            # --- Gradient Smoothing ---
            grad = grad_raw
            if grad_history is not None:
                grad_history.append(grad_raw)
                grad = np.mean(list(grad_history), axis=0)

            # --- Gradient Stabilization ---
            if args.use_signed_grad:
                grad = np.sign(grad)
            elif args.use_gradient_normalization:
                grad_norm = np.linalg.norm(grad)
                if grad_norm > 0:
                    grad = grad / (grad_norm + 1e-8)

            # Adam optimizer update
            adam_step_counter += 1
            t = adam_step_counter
            m = args.adam_beta1 * m + (1 - args.adam_beta1) * grad
            v = args.adam_beta2 * v + (1 - args.adam_beta2) * (grad ** 2)
            m_hat = m / (1 - args.adam_beta1 ** t)
            v_hat = v / (1 - args.adam_beta2 ** t)
            update_step = current_lr * m_hat / (np.sqrt(v_hat + args.adam_epsilon))
            
            if args.attack_y_channel_only:
                # When attacking Y channel, update must be applied in YUV space
                attack_image_yuv = cv2.cvtColor(attack_image.astype(np.uint8), cv2.COLOR_RGB2YUV).astype(np.float32)
                attack_image_yuv[:, :, 0] -= np.squeeze(update_step, axis=-1)
                attack_image = cv2.cvtColor(np.clip(attack_image_yuv, 0, 255).astype(np.uint8), cv2.COLOR_YUV2RGB).astype(np.float32)
            else:
                attack_image -= update_step

            perturbation = np.clip(attack_image - original_image_float, -args.l_inf_norm, args.l_inf_norm)
            attack_image = np.clip(original_image_float + perturbation, 0, 255)
            attack_image_uint8 = attack_image.astype(np.uint8)

            # Final evaluation for this iteration (use worker 0 for consistency)
            loss, hook_diagnostics, is_successful, frida_payload = workers[0].evaluate_image(attack_image, args, dynamic_weights)
            total_queries += 1
            
            iter_time = time.time() - iter_start_time
            total_time_so_far = time.time() - start_time
            print(f"Iteration result: Loss: {loss:.6f}. Iter Time: {iter_time:.2f}s. Total Time: {total_time_so_far:.2f}s")
            if frida_payload:
                print(f"  Frida Agent Output: result={frida_payload.get('result')}, output='{frida_payload.get('output')}'")

            if hook_diagnostics:
                print("  --- Hook Details ---")
                sorted_hooks = sorted(hook_diagnostics.items(), key=lambda item: item[1].get('individual_loss', 0.0), reverse=True)
                for addr, diag in sorted_hooks:
                    loss_val = diag.get('individual_loss', 0.0)
                    weight = diag.get('weight', 1.0)
                    satisfied = "SATISFIED" if diag.get('is_satisfied', False) else "NOT SATISFIED"
                    values_str = ""
                    if "values" in diag and diag["values"]:
                        # For simplicity, just show the first pair's values for console readability
                        first_pair = diag["values"][0]
                        values_str = f"| v1={first_pair['v1']:.4f}, v2={first_pair['v2']:.4f}"
                    print(f"  Hook {addr}: Loss={loss_val:<8.4f} | Weight={weight:<5.2f} | Status: {satisfied} {values_str}")

            # --- Logging, Saving, and Success Check (logic is the same) ---
            num_satisfied_hooks = sum(1 for d in hook_diagnostics.values() if d.get("is_satisfied", False))
            total_hooks = len(hook_config)
            
            hook_details_for_log = {
                addr: {"loss": round(float(diag.get("individual_loss", 0.0)), 6), "satisfied": bool(diag.get("is_satisfied", False)), "weight": diag.get("weight", 1.0), "formulas": diag.get("formulas", []), "values": diag.get("values", [])}
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

            log_data = [
                i + 1, total_queries, f"{loss:.6f}", f"{best_loss_so_far:.6f}", f"{current_lr:.6f}",
                num_satisfied_hooks, total_hooks, attack_mode, f'"{targets_str}"', f'"{hook_details_str}"', f"{iter_time:.2f}", f"{total_time_so_far:.2f}"
            ]
            detailed_log_file.write(",".join(map(str, log_data)) + "\n")
            detailed_log_file.flush()

            latest_image_path = os.path.join(args.output_dir, "latest_attack_image_spsa_parallel.png")
            cv2.imwrite(latest_image_path, cv2.cvtColor(attack_image_uint8, cv2.COLOR_RGB2BGR))

            if loss < best_loss_so_far:
                best_loss_so_far = loss
                print(f"New best loss found: {loss:.6f}. Saving best image.")
                best_image_path = os.path.join(args.output_dir, "best_attack_image_spsa_parallel.png")
                cv2.imwrite(best_image_path, cv2.cvtColor(attack_image_uint8, cv2.COLOR_RGB2BGR))

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
                    
                    for addr, state in hooks_attack_state.items():
                        if addr in hook_diagnostics:
                            state["loss_history"].append(hook_diagnostics[addr]["individual_loss"])

                    if scouting_cycle_counter >= args.evaluation_window:
                        print(f"\n--- End of Scouting Window. Analyzing results... ---")
                        
                        for addr, state in hooks_attack_state.items():
                            if len(state["loss_history"]) > 1:
                                indices = np.arange(len(state["loss_history"]))
                                slope, _, _, _, _ = stats.linregress(indices, state["loss_history"])
                                state["descent_rate"] = -slope
                            else:
                                state["descent_rate"] = 0.0
                        
                        progressing_targets = []
                        descent_threshold = args.min_loss_delta
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
                            
                            for addr, state in hooks_attack_state.items():
                                state["consecutive_satisfaction_count"] = 0
                                is_satisfied = hook_diagnostics.get(addr, {}).get("is_satisfied", False)
                                if addr in current_focus_target:
                                    state["dynamic_weight"] = args.boost_weight
                                elif is_satisfied:
                                    state["dynamic_weight"] = args.satisfied_weight
                                else:
                                    state["dynamic_weight"] = args.non_target_weight
                            
                            if args.enable_stagnation_decay:
                                stagnation_patience_counter = 0
                                best_loss_for_stagnation = float('inf')
                        else:
                            print("No hooks showed significant progress. Remaining in SCOUTING mode.")
                
                elif attack_mode == "focused_fire":
                    if not current_focus_target or not isinstance(current_focus_target, list):
                        attack_mode = "scouting"
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

                            if hooks_attack_state[target]["consecutive_satisfaction_count"] >= args.satisfaction_patience:
                                print(f"  - Target {target}: RETIRED. Assigning satisfied maintenance weight: {args.satisfied_weight}.")
                                hooks_attack_state[target]["dynamic_weight"] = args.satisfied_weight
                            else:
                                still_active_targets.append(target)
                                hooks_attack_state[target]["dynamic_weight"] = args.boost_weight
                        
                        current_focus_target = still_active_targets

                        if not current_focus_target:
                            print(f"\n--- ALL TARGETS RETIRED! ---")
                            attack_mode = "scouting"
                            current_focus_target = None
                            scouting_cycle_counter = 0
                            
                            if args.enable_stagnation_decay:
                                stagnation_patience_counter = 0
                                best_loss_for_stagnation = float('inf')

                            for addr, state in hooks_attack_state.items():
                                is_satisfied = hook_diagnostics.get(addr, {}).get("is_satisfied", False)
                                if is_satisfied:
                                    state["dynamic_weight"] = args.satisfied_weight
                                else:
                                    state["dynamic_weight"] = args.non_target_weight
                                state["loss_history"] = []
                                state["descent_rate"] = 0.0
                                state["consecutive_satisfaction_count"] = 0

            # --- Success Check ---
            if is_successful:
                print("\nAttack successful!")
                successful_image_path = os.path.join(args.output_dir, "successful_attack_image_spsa_parallel.png")
                cv2.imwrite(successful_image_path, cv2.cvtColor(attack_image_uint8, cv2.COLOR_RGB2BGR))
                break
            
            if num_satisfied_hooks == total_hooks and total_hooks > 0:
                print("\nAttack successful: All hooks are satisfied!")
                successful_image_path = os.path.join(args.output_dir, "successful_attack_image_spsa_parallel.png")
                cv2.imwrite(successful_image_path, cv2.cvtColor(attack_image_uint8, cv2.COLOR_RGB2BGR))
                break

    except Exception as e:
        print(f"\n[ERROR] An error occurred during the attack loop: {e}")
    finally:
        # --- 3. CLEANUP PHASE ---
        print("[+] Attack finished. Cleaning up all worker resources...")
        for worker in workers:
            worker.cleanup()
        print("[+] All workers cleaned up.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parallel SPSA Grey-Box Attack on Android via Frida and GDB.")
    
    # Add a new argument for number of workers
    parser.add_argument("--num-workers", type=int, default=8, help="Number of parallel attack workers to spawn.")

    # (Keep all other arguments from the original spsa_attack_android.py)
    gdb_group = parser.add_argument_group("Frida/GDB Orchestrator Settings")
    gdb_group.add_argument("--target-process", required=True, help="The target process to spawn on the device.")
    gdb_group.add_argument("--base-symbol", required=True, help="The base symbol name (e.g., library.so) for calculating GDB offsets.")
    gdb_group.add_argument("--gdb-port", type=int, default=12345, help="Base port for GDB servers. Each worker will use base_port + worker_id.")
    gdb_group.add_argument("--gdb-client", required=True, help="Path to the GDB client executable (from NDK).")

    attack_group = parser.add_argument_group("Core Attack Settings")
    attack_group.add_argument("--image", required=True, help="Local path to the initial image to be attacked.")
    attack_group.add_argument("--hooks", required=True, help="Local path to the JSON file defining hook points.")
    attack_group.add_argument("--output-dir", type=str, default="attack_outputs_spsa_parallel", help="Directory to save outputs.")
    attack_group.add_argument("--iterations", type=int, default=500, help="Maximum number of attack iterations.")
    attack_group.add_argument("--learning-rate", type=float, default=2.0)
    attack_group.add_argument("--l-inf-norm", type=float, default=20.0)
    attack_group.add_argument("--satisfaction-threshold", type=float, default=0.01)
    attack_group.add_argument("--loss-sharpness", type=float, default=8.0, help="Sharpness parameter (beta) for the Softplus loss function. Higher values make it closer to ReLU.")
    
    spsa_group = parser.add_argument_group("SPSA Settings")
    spsa_group.add_argument("--spsa-grad-samples", type=int, default=16, help="Number of gradient samples to average for SPSA. This will be distributed among workers.")
    spsa_group.add_argument("--spsa-c", type=float, default=0.1)
    spsa_group.add_argument("--spsa-c-gamma", type=float, default=0.101)
    spsa_group.add_argument("--spsa-A", type=float, default=20.0)
    
    stagnation_group = parser.add_argument_group("Stagnation-based Decay")
    stagnation_group.add_argument("--enable-stagnation-decay", action="store_true", help="Enable learning rate decay when loss stagnates.")
    stagnation_group.add_argument("--lr-decay-rate", type=float, default=0.97, help="Learning rate decay rate.")
    stagnation_group.add_argument("--lr-decay-steps", type=int, default=20, help="Decay learning rate every N steps if scheduled decay is used.")
    stagnation_group.add_argument("--stagnation-patience", type=int, default=10, help="Iterations with no improvement before forcing a decay.")
    stagnation_group.add_argument("--min-loss-delta", type=float, default=0.001, help="Minimum change in loss to be considered an improvement for stagnation.")
    
    optimizer_group = parser.add_argument_group("Optimizer Settings")
    stabilization_group = optimizer_group.add_mutually_exclusive_group()
    stabilization_group.add_argument("--use-signed-grad", action="store_true", help="Use the sign of the gradient for the update step, which can improve stability.")
    stabilization_group.add_argument("--use-gradient-normalization", action="store_true", help="Use L2 normalization on the gradient to control its magnitude, as an alternative to signed gradients.")
    optimizer_group.add_argument("--grad-smoothing-samples", type=int, default=4, help="Number of recent gradients to average for a smoother update. Set to 1 to disable.")
    optimizer_group.add_argument("--adam-beta1", type=float, default=0.9)
    optimizer_group.add_argument("--adam-beta2", type=float, default=0.999)
    optimizer_group.add_argument("--adam-epsilon", type=float, default=1e-8)
    
    dynamic_focus_group = parser.add_argument_group("Dynamic Focus Strategy (Event-Driven)")
    dynamic_focus_group.add_argument("--enable-dynamic-focus", action="store_true", help="Enable the dynamic, event-driven attack strategy.")
    dynamic_focus_group.add_argument("--evaluation-window", type=int, default=10, help="[Dynamic Focus] Number of iterations in one 'scouting' window.")
    dynamic_focus_group.add_argument("--boost-weight", type=float, default=10.0, help="[Dynamic Focus] High weight applied to the focused hook.")
    dynamic_focus_group.add_argument("--non-target-weight", type=float, default=1.0, help="[Dynamic Focus] Baseline weight for non-focused hooks.")
    dynamic_focus_group.add_argument("--satisfied-weight", type=float, default=3.0, help="[Dynamic Focus] Weight for satisfied, non-focused hooks to maintain their state.")
    dynamic_focus_group.add_argument("--satisfaction-patience", type=int, default=3, help="[Dynamic Focus] Iterations a target must be satisfied consecutively before being retired.")

    misc_group = parser.add_argument_group("Miscellaneous")
    misc_group.add_argument("--margin", type=float, default=0.005)
    misc_group.add_argument("--missing-hook-penalty", type=float, default=5)
    misc_group.add_argument("--verbose-loss", action="store_true")
    misc_group.add_argument("--verbose-gdb", action="store_true", help="Print raw GDB output and parsed hooks for debugging.")

    perturbation_group = parser.add_argument_group("Perturbation Settings")
    perturbation_group.add_argument("--resize-dim", type=int, default=0)
    perturbation_group.add_argument("--attack-y-channel-only", action="store_true", help="Perform the attack on the Y (luminance) channel only, which can be more efficient and stealthy.")

    cli_args = parser.parse_args()
    
    # A recommendation for the user
    if cli_args.spsa_grad_samples % cli_args.num_workers != 0:
        print(f"[Warning] For best performance, --spsa-grad-samples ({cli_args.spsa_grad_samples}) should be a multiple of --num-workers ({cli_args.num_workers}).")

    main(cli_args)
