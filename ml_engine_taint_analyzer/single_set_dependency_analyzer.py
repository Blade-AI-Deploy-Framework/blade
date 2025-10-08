import json
import subprocess
import tempfile
import os
import networkx as nx
from collections import deque, defaultdict
import logging
import random
import re

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class SingleSetDependencyAnalyzer:
    """
    A simplified dependency analyzer for hook configurations without set_ids.
    It assumes all hooks belong to a single implicit set and focuses on discovering
    internal control-flow dependencies (i.e., which new hooks are executed when one is flipped).
    """
    def __init__(self, hook_config_path, binary_path, input_arguments, library_path, success_marker="true", failure_marker="false"):
        self.binary_path = os.path.abspath(binary_path)
        self.input_arguments = [os.path.abspath(p) for p in input_arguments]
        self.library_path = os.path.abspath(library_path)
        self.success_marker = success_marker
        self.failure_marker = failure_marker
        
        self.dependency_graph = nx.DiGraph()
        self.known_traces = {}
        self.canonical_paths = {} # Stores the shortest path to each hook
        self.base_address = None
        
        self.hooks_by_addr = self._load_hooks(hook_config_path)

    def _load_hooks(self, path):
        with open(path, 'r') as f:
            all_hooks = json.load(f)

        # Ignore equality (b.eq) and inequality (b.ne) branch instructions in ARM
        ignored_instructions = {'b.eq', 'b.ne'}
        
        hooks_by_addr = {}
        original_hook_count = len(all_hooks)

        for h in all_hooks:
            if h.get('original_branch_instruction', '').lower() in ignored_instructions:
                logging.info(f"Ignoring hook {h['original_branch_address']} due to instruction type '{h['original_branch_instruction']}'.")
                continue
            hooks_by_addr[h['original_branch_address']] = h

        for addr in hooks_by_addr:
            self.dependency_graph.add_node(addr)
            
        loaded_count = len(hooks_by_addr)
        ignored_count = original_hook_count - loaded_count
        logging.info(f"Loading complete. Loaded {loaded_count} hooks, ignored {ignored_count}.")
        return hooks_by_addr

    def _get_base_address(self):
        """
        Gets the program's load base address via a short GDB session to handle ASLR.
        """
        if self.base_address is not None:
            return self.base_address

        gdb_script_content = "\n".join([
            "set confirm off",
            "set architecture aarch64",
            "starti",
            "info proc mappings",
            "quit"
        ])

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as tmp_script:
            tmp_script.write(gdb_script_content)
            gdb_script_path = tmp_script.name

        gdb_command = [
            "gdb-multiarch", "-q", "-batch",
            "-ex", "set debuginfod enabled off",
            "-x", gdb_script_path,
            "--args", self.binary_path
        ] + self.input_arguments

        process_env = os.environ.copy()
        process_env["LD_LIBRARY_PATH"] = f"{self.library_path}:{process_env.get('LD_LIBRARY_PATH', '')}"

        logging.info("--- Prep Phase: Getting program base address... ---")
        try:
            result = subprocess.run(gdb_command, capture_output=True, text=True, timeout=60, env=process_env)
            
            # Regex to find the base address from `info proc mappings` output.
            regex = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s+.*?" + re.escape(self.binary_path))
            
            base_address = None
            for line in result.stdout.splitlines():
                match = regex.match(line)
                if match:
                    base_address = int(match.group(1), 16)
                    logging.info(f"Successfully found base address: {hex(base_address)}")
                    break
            
            if base_address is None:
                logging.error("Could not parse base address from GDB output!")
                logging.error("GDB stdout:\n" + result.stdout)
                logging.error("GDB stderr:\n" + result.stderr)
                self.base_address = None
                return None

            self.base_address = base_address
            return self.base_address

        except subprocess.TimeoutExpired:
            logging.error("GDB session timed out while getting base address!")
            return None
        finally:
            os.remove(gdb_script_path)

    def _generate_gdb_script(self, flips_to_perform):
        script_lines = [
            "set confirm off",
            "set architecture aarch64",
            "set follow-fork-mode child",
        ]

        breakpoint_counter = 0
        for addr_str, hook in self.hooks_by_addr.items():
            breakpoint_counter += 1
            
            offset = int(addr_str, 16)
            real_addr = hex(self.base_address + offset)
            script_lines.append(f"break *{real_addr}")
            
            cmd = [f"command {breakpoint_counter}"]
            cmd.append("silent")
            
            is_flipped_hook = addr_str in flips_to_perform
            
            if is_flipped_hook:
                branch_target_offset_str = hook.get('branch_target')
                instr_type = hook.get('original_branch_instruction', '').lower()

                if not branch_target_offset_str or branch_target_offset_str == 'N/A':
                    cmd.append(f'printf "HOOK_HIT_NO_FLIP_METHOD: {addr_str} (missing branch_target in config for {instr_type})\\n"')
                else:
                    cmd.append(f'printf "FLIP_ATTEMPT: {addr_str} by forcing alternative path for {instr_type}\\n"')
                    
                    branch_target_offset = int(branch_target_offset_str, 16)
                    real_branch_target = hex(self.base_address + branch_target_offset)
                    real_fallthrough_addr = hex(self.base_address + offset + 4)

                    cmd.append("set $orig_pc = $pc")
                    cmd.append(f"set $jump_target = {real_branch_target}")
                    cmd.append(f"set $fallthrough_addr = {real_fallthrough_addr}")
                    cmd.append(f"printf \"FLIP_DEBUG: Forcing flip at {addr_str}. Jump Target: 0x%x, Fallthrough: 0x%x\\n\", $jump_target, $fallthrough_addr")
                    cmd.append("stepi")
                    # After stepi, $pc is at the next location.
                    # If the original instruction was a branch and was taken, then $pc == $jump_target.
                    cmd.append("if $pc == $jump_target")
                    cmd.append(f'  printf "FLIP_INFO: Branch at {addr_str} was TAKEN. Forcing fall-through to 0x%x\\n", $fallthrough_addr')
                    cmd.append("  jump *$fallthrough_addr")
                    # Otherwise, the branch was not taken, or it wasn't a branch instruction.
                    cmd.append("else")
                    cmd.append(f'  printf "FLIP_INFO: Branch at {addr_str} was NOT taken. Forcing jump to 0x%x\\n", $jump_target')
                    cmd.append("  jump *$jump_target")
                    cmd.append('  printf "DEBUG_AFTER_JUMP: Landed at 0x%x.\\n", $pc')
                    cmd.append("  x/i $pc")
                    cmd.append("end")
                    cmd.append(f'printf "FLIP_DONE: {addr_str}\\n"')

            else:
                cmd.append(f'printf "HOOK_HIT: {addr_str}\\n"')
                
            cmd.append("continue")
            cmd.append("end")
            script_lines.extend(cmd)

        # Use stdbuf to force line-buffering on stdout to ensure markers are flushed immediately.
        script_lines.append("set exec-wrapper stdbuf -o0 -e0")

        script_lines.append("run")
        script_lines.append("quit")
        
        return "\n".join(script_lines)

    def _run_gdb_session(self, flips_to_perform=None):
        flips_to_perform = flips_to_perform or {}
        
        flips_key = frozenset(flips_to_perform.keys())
        if flips_key in self.known_traces:
            logging.info(f"Cache hit, skipping GDB execution. Flip points: {list(flips_key)}")
            return self.known_traces[flips_key]

        gdb_script_content = self._generate_gdb_script(flips_to_perform)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as tmp_script:
            tmp_script.write(gdb_script_content)
            gdb_script_path = tmp_script.name
        
        gdb_command = [
            "gdb-multiarch", "-q", "-batch", 
            "-ex", "set debuginfod enabled off",
            "-x", gdb_script_path,
            "--args", self.binary_path
        ] + self.input_arguments

        logging.info(f"Executing GDB session... Flip points: {list(flips_to_perform.keys())}")
        
        process_env = os.environ.copy()
        process_env["LD_LIBRARY_PATH"] = f"{self.library_path}:{process_env.get('LD_LIBRARY_PATH', '')}"

        try:
            # Use env parameter to pass environment variables
            result = subprocess.run(gdb_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180, env=process_env)
            
            trace = []
            output_lines = result.stdout.splitlines()
            for line in output_lines:
                if line.startswith("HOOK_HIT:") or line.startswith("FLIP_DONE:") or line.startswith("HOOK_HIT_NO_FLIP_METHOD:"):
                    parts = line.split(":")
                    if len(parts) > 1:
                        addr = parts[1].strip().split(" ")[0]
                        trace.append(addr)
                elif "FLIP_INFO" in line:
                    logging.debug(line)

            # Check if all flipped hooks were actually traced. If not, it may indicate a crash.
            flipped_hooks_in_trace = {addr for addr in trace if addr in flips_to_perform}
            if len(flipped_hooks_in_trace) != len(flips_to_perform):
                logging.warning(
                    f"Not all flipped hooks appeared in the trace! Flipped: {list(flips_to_perform.keys())}, "
                    f"Seen in trace's flip-set: {list(flipped_hooks_in_trace)}"
                )
                logging.warning("--- GDB stdout for this session ---")
                logging.warning(result.stdout)
                logging.warning("--- GDB stderr for this session ---")
                logging.warning(result.stderr or "(GDB stderr was empty)")
                logging.warning("------------------------------------")

            if not trace and (result.stdout or result.stderr):
                logging.warning("GDB session might have had an issue. Stdout:\n" + result.stdout)

            logging.debug(f"--- GDB stdout for flips {list(flips_to_perform.keys())} ---")
            logging.debug(result.stdout)
            logging.debug("--- End of GDB stdout ---")

            logging.info(f"Execution complete. Trace length: {len(trace)}. Trace: {trace}")
            
            execution_result = (trace, result.stdout, result.stderr)
            self.known_traces[flips_key] = execution_result
            return execution_result

        except subprocess.TimeoutExpired:
            logging.error("GDB session timed out!")
            execution_result = ([], "", "GDB session timed out!")
            self.known_traces[flips_key] = execution_result
            return execution_result
        finally:
            os.remove(gdb_script_path)

    def analyze(self):
        if self._get_base_address() is None:
            logging.error("Could not get base address, aborting analysis.")
            return

        logging.info("--- Stage 1: Get baseline execution trace ---")
        baseline_trace, baseline_stdout, _ = self._run_gdb_session()
        if not baseline_trace:
            logging.error("Could not get baseline trace, aborting analysis.")
            if self.failure_marker and self.failure_marker in baseline_stdout:
                logging.error(f"Baseline execution failed with marker: '{self.failure_marker}'")
            return

        task_queue = deque()
        processed_tasks = set() 

        logging.info("--- Initializing task queue ---")
        for hook_addr in baseline_trace:
            if hook_addr in self.hooks_by_addr:
                task = (hook_addr, ())
                if task not in processed_tasks:
                    task_queue.append(task)
                    processed_tasks.add(task)
                    if hook_addr not in self.canonical_paths:
                        self.canonical_paths[hook_addr] = ()

        logging.info(f"Initialization complete. Task queue contains {len(task_queue)} initial tasks.")

        while task_queue:
            target_addr, prereq_flips_tuple = task_queue.popleft()
            prereq_flips = frozenset(prereq_flips_tuple)

            logging.info(f"\n{'='*20} Exploring: Flipping {target_addr} (source path: {prereq_flips_tuple}) {'='*20}")
            
            current_flips_set = prereq_flips | {target_addr}
            current_path_tuple = prereq_flips_tuple + (target_addr,)
            
            flipped_trace, flipped_stdout, _ = self._run_gdb_session({addr: self.hooks_by_addr[addr] for addr in current_flips_set})

            # Check for explicit failure marker from program output
            if self.failure_marker and self.failure_marker in flipped_stdout:
                logging.info(f"==> Dependency Discovered: {target_addr} -> PROGRAM_FAILURE")
                self.dependency_graph.add_edge(
                    target_addr,
                    "PROGRAM_FAILURE",
                    trigger_path=current_path_tuple
                )
                continue

            # Check for crash/implicit termination, unless success is explicitly reported
            has_crashed = target_addr not in flipped_trace
            is_successful = self.success_marker and self.success_marker in flipped_stdout
            if has_crashed and not is_successful:
                logging.info(f"==> Dependency Discovered: {target_addr} -> PROGRAM_TERMINATION")
                self.dependency_graph.add_edge(
                    target_addr, 
                    "PROGRAM_TERMINATION", 
                    trigger_path=current_path_tuple
                )
                continue

            if not flipped_trace and not is_successful:
                continue

            parent_trace_tuple = self.known_traces.get(prereq_flips)
            if parent_trace_tuple is None:
                logging.info(f"Cache miss, generating parent trace for path {prereq_flips_tuple}...")
                parent_trace_tuple = self._run_gdb_session({addr: self.hooks_by_addr[addr] for addr in prereq_flips})
                if not parent_trace_tuple[0]:
                   logging.error(f"Logic Error: Could not generate parent trace (prereqs: {list(prereq_flips)}).")
                   continue
            
            parent_trace = parent_trace_tuple[0]

            new_hooks_in_trace = set(flipped_trace) - set(parent_trace)
            for new_hook_addr in new_hooks_in_trace:
                if new_hook_addr not in self.hooks_by_addr:
                    continue
                
                if new_hook_addr in self.canonical_paths and len(current_path_tuple) >= len(self.canonical_paths[new_hook_addr]):
                    continue 

                logging.info(f"==> Dependency Discovered: {target_addr} -> {new_hook_addr}")
                self.dependency_graph.add_edge(
                    target_addr, 
                    new_hook_addr, 
                    trigger_path=current_path_tuple
                )

                self.canonical_paths[new_hook_addr] = current_path_tuple
                new_task = (new_hook_addr, current_path_tuple)
                
                if new_task not in processed_tasks:
                    task_queue.append(new_task)
                    processed_tasks.add(new_task)
                    logging.info(f"New task added to queue: Flip {new_hook_addr} (source path: {current_path_tuple})")

        logging.info("--- All analysis tasks complete ---")
        self._print_results()

    def _print_results(self):
        print("\n" + "="*20 + " Final Dependency Graph " + "="*20)
        if not self.dependency_graph.edges:
            print("No dependencies were discovered.")
            return

        dependencies = defaultdict(list)
        terminations = []
        failures = []
        for u, v, data in self.dependency_graph.edges(data=True):
            if v == "PROGRAM_TERMINATION":
                terminations.append((u, data))
            elif v == "PROGRAM_FAILURE":
                failures.append((u, data))
            else:
                dependencies[u].append((v, data))

        if dependencies:
            print("\n  --- Internal Dependencies (Flipping hook A leads to reaching hook B) ---")
            for trigger_addr in sorted(dependencies.keys()):
                trigger_instr = self.hooks_by_addr.get(trigger_addr, {}).get('instruction', 'N/A')
                print(f"\n    >> Flipping {trigger_addr} ({trigger_instr}) reveals:")
                
                for discovered_addr, data in sorted(dependencies[trigger_addr]):
                    path = data.get('trigger_path', 'N/A')
                    print(f"      - Hook: {discovered_addr} (via path: {path})")
        
        if terminations:
            print("\n  --- Hooks Leading to Termination ---")
            for trigger_addr, data in sorted(terminations):
                trigger_instr = self.hooks_by_addr.get(trigger_addr, {}).get('instruction', 'N/A')
                path = data.get('trigger_path', 'N/A')
                print(f"    >> Flipping {trigger_addr} ({trigger_instr}) with path {path} leads to program termination.")

        if failures:
            print(f"\n  --- Hooks Leading to Failure (marker: '{self.failure_marker}') ---")
            for trigger_addr, data in sorted(failures):
                trigger_instr = self.hooks_by_addr.get(trigger_addr, {}).get('instruction', 'N/A')
                path = data.get('trigger_path', 'N/A')
                print(f"    >> Flipping {trigger_addr} ({trigger_instr}) with path {path} leads to program failure.")
    
        print("\nYou can use NetworkX to visualize the graph.")


if __name__ == '__main__':
    HOOK_CONFIG_PATH = './results/gender_googlenet_mnn_hook_config.json'
    
    BINARY_PATH = './assets/successful_executables/gender_googlenet_mnn'
    
    # As per your description, the program needs two arguments: model path and image path
    INPUT_ARGUMENTS = [
        './assets/gender_googlenet.mnn', # Argument 1: Model Path
        './assets/images/test_lite_gender_googlenet.jpg'     # Argument 2: Image Path
    ]

    # Update the library path based on your `find` command results
    LD_LIBRARY_PATH= './third_party/mnn/lib'
    
    analyzer = SingleSetDependencyAnalyzer(
        hook_config_path=HOOK_CONFIG_PATH,
        binary_path=BINARY_PATH,
        input_arguments=INPUT_ARGUMENTS,
        library_path=LD_LIBRARY_PATH,
        success_marker="true",
        failure_marker="false"
    )
    analyzer.analyze() 