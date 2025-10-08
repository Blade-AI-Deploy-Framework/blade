import json
import subprocess
import tempfile
import os
import networkx as nx
from collections import deque, defaultdict
import logging
import random

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DependencyAnalyzer:
    def __init__(self, hook_config_path, binary_path, initial_input_path, docker_image):
        self.hooks_by_addr = self._load_hooks(hook_config_path)
        self.binary_path = binary_path
        self.initial_input_path = initial_input_path
        self.docker_image = docker_image
        
        self.dependency_graph = nx.DiGraph()
        self.known_traces = {}
        self.analysis_queue = deque()
        self.negative_dependencies = {} 
        self.canonical_paths = {}

    def _load_hooks(self, path):
        with open(path, 'r') as f:
            hooks = json.load(f)
        
        all_sets = {hook['set_id'] for hook in hooks}
        for s in all_sets:
            self.dependency_graph.add_node(s, hooks=[])

        hooks_by_addr = {h['address']: h for h in hooks}
        
        for addr, hook in hooks_by_addr.items():
            self.dependency_graph.nodes[hook['set_id']]['hooks'].append(addr)
            
        logging.info(f"Successfully loaded {len(hooks_by_addr)} hooks, covering {len(all_sets)} sets.")
        return hooks_by_addr

    def _generate_gdb_script(self, flips_to_perform):
        script_lines = [
            "set pagination off",
            "set confirm off",
            "set architecture aarch64",
        ]

        breakpoint_counter = 0
        for addr, hook in self.hooks_by_addr.items():
            breakpoint_counter += 1
            script_lines.append(f"break *{addr}")
            
            cmd = [f"command {breakpoint_counter}"]
            cmd.append("silent")
            
            is_flipped_hook = addr in flips_to_perform
            
            if is_flipped_hook:
                branch_target = hook.get('branch_target')
                instr_type = hook.get('instruction', '').lower()

                if not branch_target:
                    cmd.append(f'printf "HOOK_HIT_NO_FLIP_METHOD: {addr} (missing branch_target in config for {instr_type})\\n"')
                else:
                    cmd.append(f'printf "FLIP_ATTEMPT: {addr} by forcing alternative path for {instr_type}\\n"')
                    
                    cmd.append("set $orig_pc = $pc")
                    cmd.append(f"set $jump_target = {branch_target}")
                    cmd.append("set $fallthrough_addr = $orig_pc + 4")
                    
                    # Step over the original instruction to see where it goes
                    cmd.append("stepi") 
                    
                    cmd.append("if $pc == $jump_target")
                    cmd.append("  printf \\\"FLIP_INFO: Branch at 0x%x was TAKEN. Forcing fall-through to 0x%x\\n\\\", $orig_pc, $fallthrough_addr")
                    cmd.append("  jump *$fallthrough_addr")
                    cmd.append("else")
                    cmd.append("  printf \\\"FLIP_INFO: Branch at 0x%x was NOT taken. Forcing jump to 0x%x\\n\\\", $orig_pc, $jump_target")
                    cmd.append("  jump *$jump_target")
                    cmd.append("end")
                    cmd.append(f'printf "FLIP_DONE: {addr}\\n"')

            else:
                cmd.append(f'printf "HOOK_HIT: {addr}\\n"')
                
            cmd.append("continue")
            cmd.append("end")
            script_lines.extend(cmd)

        script_lines.append(f"run /work/{os.path.basename(self.binary_path)} /work/{os.path.basename(self.initial_input_path)}")
        script_lines.append("quit")
        
        return "\\n".join(script_lines)

    def _run_gdb_session(self, flips_to_perform=None):
        flips_to_perform = flips_to_perform or {}
        
        flips_key = frozenset(flips_to_perform.keys())
        if flips_key in self.known_traces:
            logging.info(f"Cache hit, skipping GDB execution. Flip points: {list(flips_key)}")
            return self.known_traces[flips_key]

        gdb_script_content = self._generate_gdb_script(flips_to_perform)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.gdb') as tmp_script:
            tmp_script.write(gdb_script_content)
            gdb_script_path_host = tmp_script.name
        
        binary_dir = os.path.dirname(os.path.abspath(self.binary_path))
        input_dir = os.path.dirname(os.path.abspath(self.initial_input_path))
        script_dir = os.path.dirname(gdb_script_path_host)

        gdb_script_path_container = f"/work/{os.path.basename(gdb_script_path_host)}"

        docker_command = [
            "docker", "run", "--rm",
            "-v", f"{binary_dir}:/work",
            "-v", f"{input_dir}:/work",
            "-v", f"{script_dir}:/work",
            self.docker_image,
            "gdb", "-q", "-x", gdb_script_path_container
        ]

        logging.info(f"Executing GDB session... Flip points: {list(flips_to_perform.keys())}")
        
        try:
            result = subprocess.run(docker_command, capture_output=True, text=True, timeout=60)
            
            trace = []
            output_lines = result.stdout.splitlines()
            for line in output_lines:
                if line.startswith("HOOK_HIT:") or line.startswith("FLIP_DONE:"):
                    parts = line.split(":")
                    if len(parts) > 1:
                        addr = parts[1].strip().split(" ")[0]
                        trace.append(addr)
                elif "FLIP_INFO" in line:
                    logging.debug(line)

            if not trace and (result.stdout or result.stderr):
                 logging.warning("GDB session might have encountered an issue. STDOUT:\n" + result.stdout)
                 logging.warning("GDB session might have encountered an issue. STDERR:\n" + result.stderr)

            logging.info(f"Execution complete. Trace length: {len(trace)}. Trace: {trace}")
            
            self.known_traces[flips_key] = trace
            return trace

        except subprocess.TimeoutExpired:
            logging.error("GDB session timed out!")
            self.known_traces[flips_key] = []
            return []
        finally:
            os.remove(gdb_script_path_host)

    def analyze(self):
        # Phase 1: Baseline Analysis and Initialization
        logging.info("--- Phase 1: Getting baseline execution trace and source info ---")
        baseline_trace = self._run_gdb_session()
        if not baseline_trace:
            logging.error("Could not get baseline trace, analysis aborted.")
            return

        # self.dependency_graph will store path relationships
        # self.hooks_by_addr stores source info by address

        master_queue = deque()
        set_internal_queues = defaultdict(deque)
        
        # Initial Queue Population
        logging.info("--- Initializing task queues ---")
        if baseline_trace and baseline_trace[0] in self.hooks_by_addr:
            start_set_id = self.hooks_by_addr[baseline_trace[0]]['set_id']
            master_queue.append(start_set_id)
            logging.info(f"Analysis starting point determined: Set '{start_set_id}'. Added to the main task queue.")
        else:
            logging.error(f"The first hook address {baseline_trace[0]} from the baseline trace is not in the config. Cannot determine start set.")
            return

        processed_master_tasks = {start_set_id} 
        for hook_addr in baseline_trace:
            if hook_addr in self.hooks_by_addr:
                set_id = self.hooks_by_addr[hook_addr]['set_id']
                if set_id in set_internal_queues:
                    task = (hook_addr, tuple()) 
                    set_internal_queues[set_id].append(task)
                    if hook_addr not in self.canonical_paths:
                        self.canonical_paths[hook_addr] = tuple()


        logging.info(f"Initialization complete. Main queue contains {len(master_queue)} sets.")

        # Phase 2: Main Loop - Process each set sequentially
        completed_sets = set()
        while master_queue:
            current_set_id = master_queue.popleft()
            
            if current_set_id in completed_sets:
                continue

            logging.info(f"\n{'='*20} Starting to process Set: {current_set_id} {'='*20}")
            internal_queue = set_internal_queues[current_set_id]
            
            processed_internal_tasks = set() 
            
            while internal_queue:
                target_addr, prereq_flips_tuple = internal_queue.popleft()

                if (target_addr, prereq_flips_tuple) in processed_internal_tasks:
                    continue
                processed_internal_tasks.add((target_addr, prereq_flips_tuple))
                
                logging.info(f"--> [Set: {current_set_id}] Internal exploration: Flipping {target_addr} (Source path: {prereq_flips_tuple})")

                prereq_flips = dict(prereq_flips_tuple)
                current_flips = prereq_flips.copy()
                current_flips[target_addr] = self.hooks_by_addr[target_addr]['instruction']
                new_trace = self._run_gdb_session(current_flips)
                
                if not new_trace: continue

                # Get the parent trace for comparison
                parent_trace = self.known_traces.get(prereq_flips_tuple)
                if parent_trace is None:
                    logging.info(f"Cache miss, generating parent trace for path {prereq_flips_tuple}...")
                    parent_trace = self._run_gdb_session(prereq_flips)
                    if not parent_trace:
                       logging.error(f"Logic error: Could not generate parent trace (prereqs: {list(prereq_flips)}).")
                       continue

                # --- Dependency Determination ---
                
                current_path_tuple = tuple(sorted(current_flips.keys()))

                # Inter-Set Dependency
                newly_reached_hooks = set(new_trace) - set(parent_trace)
                for hook_addr in newly_reached_hooks:
                    if hook_addr in self.hooks_by_addr and self.hooks_by_addr[hook_addr]['set_id'] != current_set_id:
                        new_set = self.hooks_by_addr[hook_addr]['set_id']
                        logging.info(f"★★★ Inter-set dependency found: From {current_set_id} to {new_set} (by flipping {target_addr})")
                        self.dependency_graph.add_edge(current_set_id, new_set, type='positive', 
                                                       trigger_address=target_addr, 
                                                       trigger_instruction=self.hooks_by_addr[target_addr]['instruction'])
                        if new_set not in processed_master_tasks:
                            master_queue.append(new_set)
                            processed_master_tasks.add(new_set)
                            logging.info(f"New set '{new_set}' has been added to the main queue for later analysis.")

                        # Add initial tasks for the new set's internal queue
                        if new_set in set_internal_queues:
                            if hook_addr in self.canonical_paths:
                                continue 
                            task = (hook_addr, current_path_tuple)
                            self.canonical_paths[hook_addr] = current_path_tuple 
                            set_internal_queues[new_set].append(task)

                # Negative Dependency Logic
                lost_hooks = set(parent_trace) - set(new_trace)
                for hook_addr in lost_hooks:
                    if hook_addr in self.hooks_by_addr and self.hooks_by_addr[hook_addr]['set_id'] != current_set_id:
                        lost_set = self.hooks_by_addr[hook_addr]['set_id']
                        logging.info(f"Negative dependency found: Flipping {target_addr} (in {current_set_id}) causes set {lost_set} to become unreachable.")
                        self.dependency_graph.add_edge(current_set_id, lost_set, type='negative', 
                                                       trigger_address=target_addr, 
                                                       trigger_instruction=self.hooks_by_addr[target_addr]['instruction'])


                # Intra-Set Dependency (within the same set)
                for new_hook_addr in newly_reached_hooks:
                    if new_hook_addr in self.hooks_by_addr and self.hooks_by_addr[new_hook_addr]['set_id'] == current_set_id:
                        self.dependency_graph.add_edge(target_addr, new_hook_addr, set_id=current_set_id)
                        
                        if new_hook_addr in self.canonical_paths:
                            continue 
                        task = (new_hook_addr, current_path_tuple)
                        
                        # Pruning Logic
                        is_pruned = False
                        for prereq_hook_addr in prereq_flips:
                            if current_set_id in self.negative_dependencies.get(prereq_hook_addr, set()):
                                logging.info(f"Pruning: Task skipped because prerequisite flip {prereq_hook_addr} makes target set {current_set_id} unreachable.")
                                is_pruned = True
                                break
                        if not is_pruned:
                            set_internal_queues[current_set_id].append(task)
                            logging.info(f"==> [Set: {current_set_id}] Intra-set dependency found: {target_addr} -> {new_hook_addr}. Added to internal queue.")
                            self.canonical_paths[new_hook_addr] = current_path_tuple 

            logging.info(f"\n{'='*20} Internal analysis for set {current_set_id} complete {'='*20}")
            completed_sets.add(current_set_id)

        logging.info("--- All analysis tasks complete ---")
        self._print_results()

    def _print_results(self):
        print("\n" + "="*20 + " Final Dependency Graph " + "="*20)
        if not self.dependency_graph.edges:
            print("No dependencies were found.")
            return

        from collections import defaultdict
        positive_edges = []
        negative_edges = []
        intra_set_edges = defaultdict(list)

        for u, v, data in self.dependency_graph.edges(data=True):
            dep_type = data.get('type')
            if dep_type == 'positive':
                positive_edges.append((u, v, data))
            elif dep_type == 'negative':
                negative_edges.append((u, v, data))
            elif 'set_id' in data:
                triggering_set = data.get('set_id', 'Unknown Set')
                intra_set_edges[triggering_set].append((u, v, data))

        if positive_edges:
            print("\n  --- Positive Inter-Set Dependencies (Flipping A leads to reaching B) ---")
            for u, v, data in sorted(positive_edges):
                print(f"    - From Set '{u}' to Set '{v}':")
                print(f"      Triggered by: flipping address {data['trigger_address']} (instruction: '{data['trigger_instruction']}')")
        
        if negative_edges:
            print("\n  --- Negative Inter-Set Dependencies (Flipping A prevents reaching B) ---")
            for u, v, data in sorted(negative_edges):
                print(f"    - Flipping {data['trigger_address']} in Set '{u}' (instruction: '{data['trigger_instruction']}')")
                print(f"      causes Set '{v}' to become unreachable.")

        if intra_set_edges:
            print("\n  --- Intra-Set Dependencies (Flipping hook A leads to reaching hook B) ---")
            
            grouped_by_set = {}
            for u, v, data in intra_set_edges.items():
                set_id = data['set_id']
                if set_id not in grouped_by_set:
                    grouped_by_set[set_id] = []
                grouped_by_set[set_id].append((u, v))
            
            for set_id, edges in grouped_by_set.items():
                print(f"\n    >> Inside Set '{set_id}':")
                for u, v in edges:
                    trigger_instr = self.hooks_by_addr.get(u, {}).get('instruction', 'N/A')
                    print(f"      - Flipping {u} ({trigger_instr}) ==> discovered {v}")

        print("\nThe graph can be visualized using NetworkX.")


if __name__ == '__main__':
    HOOK_CONFIG_PATH = 'model_deploy_execution_attack/hook_config/emotion_ferplus_mnn_hook_config.json'
    
    BINARY_PATH = 'test_taint/mnist_mnn_console'
    
    INITIAL_INPUT_PATH = 'test_taint/1.txt'
    
    DOCKER_IMAGE = 'my-gdb-runner-image'

    analyzer = DependencyAnalyzer(
        hook_config_path=HOOK_CONFIG_PATH,
        binary_path=BINARY_PATH,
        initial_input_path=INITIAL_INPUT_PATH,
        docker_image=DOCKER_IMAGE
    )
    analyzer.analyze()
