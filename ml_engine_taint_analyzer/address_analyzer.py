# address_analyzer.py
# Starts taint analysis from a user-specified function call address. It taints
# all arguments and the return value of that call, then continues analysis
# within the current function without recursing into the initial call.

# Ghidra Script Boilerplate
try:
    _current_program = currentProgram
    _current_address = currentAddress
    _monitor = monitor
    _println = println
    _printerr = printerr
    _askFile = askFile
    _askAddress = askAddress
except NameError:
    # This block is for developing outside Ghidra, e.g., with ghidra_bridge.
    # It should not be reached in headless mode.
    import sys
    _current_program = None
    _current_address = None
    _monitor = None
    _println = lambda msg: sys.stdout.write(str(msg) + "\n")
    _printerr = lambda msg: sys.stderr.write(str(msg) + "\n")
    _askFile = None
    _askAddress = None
    # Add script directory to path to allow importing our modules
    import os
    # Assuming the script is in the same directory as generic_taint_analyzer
    sys.path.append(os.path.dirname(os.path.realpath(__file__)))

# Import the generic analyzer and other necessary modules
try:
    from generic_taint_analyzer import TaintAnalyzer
except ImportError:
    print("ERROR: Could not find 'generic_taint_analyzer.py'.")
    print("Please ensure it is in the same directory as this script or in Ghidra's script paths.")
    sys.exit(1)

import sys
import json
import os
import re


def create_initial_call_rule_handler(target_call_op_to_ignore):
    """
    Creates a rule handler to specifically ignore the initial target call,
    preventing recursion.
    """
    def rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
        current_pcode_op = all_pcode_ops[op_idx]
        
        # Ignore the specific pcode op we started from
        if current_pcode_op.getSeqnum().equals(target_call_op_to_ignore.getSeqnum()):
            analyzer.println("INFO: [RULE address_analyzer] Ignoring initial call to prevent recursion: {}".format(current_pcode_op))
            return True # Signal that we've handled this; stop default processing.
        
        # Let the generic analyzer handle all other ops.
        return False
        
    return rule_handler


def cleanup_operand_repr(repr_str):
    """
    Cleans up Ghidra varnode representation string.
    e.g., "UNNAMED(s7)" -> "s7", "Constant: 0x10" -> "0x10"
    """
    if not isinstance(repr_str, basestring): # Jython compatibility
        repr_str = str(repr_str)

    # Extract content from parentheses
    match = re.search(r'\((.*?)\)', repr_str)
    if match:
        repr_str = match.group(1)
    
    # Handle "Type: Value" format
    if ': ' in repr_str:
        return repr_str.split(': ', 1)[1]

    return repr_str

def generate_comparison_json(analyzer):
    """
    Generates a JSON file with all tainted comparisons found during analysis.
    """
    if not analyzer.all_tainted_usages:
        analyzer.println("No tainted usages found, skipping JSON generation.")
        return

    comparison_entries = []
    processed_entries = set()

    for usage in analyzer.all_tainted_usages:
        if usage.get("usage_type") == "TAINTED_COMPARISON":
            address_str = usage.get("address", "N/A")
            
            pcode_op_str = usage.get("pcode_op_str", "N/A")
            raw_operands = usage.get("compared_ops_repr", [])
            cleaned_operands = [cleanup_operand_repr(op) for op in raw_operands]
            
            # Use a tuple to uniquely identify this comparison to avoid duplicates
            entry_tuple = (address_str, pcode_op_str, tuple(cleaned_operands))
            if address_str == "N/A" or entry_tuple in processed_entries:
                continue
            processed_entries.add(entry_tuple)

            entry = {
                "address": address_str,
                "instruction": usage.get("instruction_mnemonic", "N/A").lower(),
                "pcode_operation": pcode_op_str,
                "operands": cleaned_operands,
                "details": usage.get("details", "")
            }
            comparison_entries.append(entry)

    if not comparison_entries:
        analyzer.println("No tainted comparisons found to generate a JSON file.")
        return

    # Determine output path for the JSON file
    output_file_path = os.getenv('TAINT_ANALYSIS_JSON_OUTPUT')
    if output_file_path:
        analyzer.println("INFO: Using TAINT_ANALYSIS_JSON_OUTPUT env var for output path: {}".format(output_file_path))
    else:
        analyzer.println("INFO: TAINT_ANALYSIS_JSON_OUTPUT env var not set. Using default path construction.")
        script_dir = os.path.dirname(os.path.realpath(__file__))
        results_dir = os.path.join(script_dir, "results")
        
        if not os.path.exists(results_dir):
            try:
                os.makedirs(results_dir)
            except OSError:
                pass

        program_name = analyzer.current_program.getName()
        output_filename = "{}_comparison_results.json".format(program_name)
        output_file_path = os.path.join(results_dir, output_filename)

    # Ensure the final output directory exists
    output_dir = os.path.dirname(output_file_path)
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
        except OSError:
            pass # Suppress error if directory was created between check and makedirs

    try:
        with open(output_file_path, 'w') as f:
            json.dump(comparison_entries, f, indent=4)
        analyzer.println("SUCCESS: Tainted comparison results saved to: {}".format(output_file_path))
    except Exception as e:
        analyzer.printerr("ERROR: Could not write comparison results to file {}: {}".format(output_file_path, e))


def run_analysis_from_ghidra_ui():
    """
    Main entry point. In UI, prompts for an address. In headless mode,
    reads address from script arguments.
    """
    if not all((_current_program, _monitor, _println, _printerr, _askFile)):
        sys.stderr.write("Error: This script must be run within a full Ghidra environment.\n")
        return

    analyzer = None
    try:
        # Get the starting address from args or user prompt
        target_address = None
        try:
            script_args = getScriptArgs()
            if script_args and len(script_args) > 0:
                target_address_str = script_args[0]
                target_address = _current_program.getAddressFactory().getAddress(target_address_str)
            else:
                _askAddress_func = globals().get('_askAddress')
                if _askAddress_func:
                    target_address = _askAddress_func("Start Taint Analysis", "Enter the address of the function call to start from:")
        except Exception as e:
            _printerr("Could not get or parse address: {}".format(e))
            return

        if not target_address:
            _println("Analysis cancelled or address not provided.")
            return

        # Find parent function and decompile
        parent_func = _current_program.getFunctionManager().getFunctionContaining(target_address)
        if not parent_func:
            _printerr("ERROR: No function found containing address {}. Aborting.".format(target_address))
            return

        # Initialize analyzer
        analyzer = TaintAnalyzer(
            current_program=_current_program,
            monitor=_monitor,
            println=_println,
            printerr=_printerr,
            askFile=_askFile
        )

        # Decompile function to find the target call op
        decompile_results = analyzer.decompiler.decompileFunction(parent_func, 60, analyzer.monitor)
        if not decompile_results or not decompile_results.getHighFunction():
            _printerr("ERROR: Failed to decompile parent function {}. Aborting.".format(parent_func.getName()))
            return
        high_parent_func = decompile_results.getHighFunction()

        # Find the target call p-code op
        target_call_op = None
        op_iter = high_parent_func.getPcodeOps(target_address)
        while op_iter.hasNext():
            pcode_op = op_iter.next()
            if pcode_op.getMnemonic() in ["CALL", "CALLIND"]:
                target_call_op = pcode_op
                break
        
        if not target_call_op:
            _printerr("ERROR: No CALL or CALLIND P-code operation found at address {}. Aborting.".format(target_address))
            return

        # Create and add the rule to ignore the initial call
        ignore_rule = create_initial_call_rule_handler(target_call_op)
        analyzer.rule_handlers.append(ignore_rule)
        
        _println("INFO: Starting analysis from address: {}".format(target_address))
        _println("INFO: Found call operation: {}".format(target_call_op))

        # Create the initial set of tainted variables
        initial_tainted_hvs = set()
        stack_offsets_to_taint = set()

        # Taint the return value (output) of the call
        output_vn = target_call_op.getOutput()
        if output_vn:
            output_hv = output_vn.getHigh()
            if output_hv:
                initial_tainted_hvs.add(output_hv)
                _println("INFO: Tainting return value: {}".format(analyzer._get_varnode_representation(output_hv, high_parent_func)))
            else:
                _println("INFO: Call has no HighVariable for its output. Nothing to taint.")
        else:
            _println("INFO: Call has no return value to taint.")

        # Taint all input arguments of the call
        # P-code inputs for a call are [call_target, arg1, arg2, ...]
        for pcode_arg_idx in range(1, target_call_op.getNumInputs()):
            arg_vn = target_call_op.getInput(pcode_arg_idx)
            if arg_vn:
                _println("\n--- DEBUG: Analyzing Argument #{} ---".format(pcode_arg_idx - 1))
                _println("  - Argument Varnode: {}".format(arg_vn))
                def_op = arg_vn.getDef()
                if def_op:
                    _println("  - Def P-Code Op:    {}".format(def_op))
                else:
                    _println("  - Def P-Code Op:    None")

                arg_hv = arg_vn.getHigh()
                if arg_hv:
                    _println("  - HighVariable:       {}".format(analyzer._get_varnode_representation(arg_hv, high_parent_func)))

                    # Heuristic: Find stack vars passed as pointers to taint their contents.
                    # This is now handled by the generic analyzer; we just taint the arg's HighVariable.
                    initial_tainted_hvs.add(arg_hv)
                    _println("INFO: Tainting argument #{}: {}".format(pcode_arg_idx - 1, analyzer._get_varnode_representation(arg_hv, high_parent_func)))
                else:
                    _println("WARN: Argument #{} has no HighVariable. Cannot taint.".format(pcode_arg_idx - 1))
                
                _println("--- END DEBUG: Analyzing Argument #{} ---".format(pcode_arg_idx - 1))
        
        if not initial_tainted_hvs and not stack_offsets_to_taint:
            _printerr("ERROR: Could not identify any high variables or stack pointers to taint from the specified call. Aborting.")
            return

        # Start the taint trace within the parent function
        _println("\n--- Initiating Taint Analysis for: {} (starting after call at {}) ---".format(parent_func.getName(), target_address))
        
        analyzer._trace_taint_in_function(
            high_func_to_analyze=high_parent_func,
            initial_tainted_hvs=initial_tainted_hvs,
            pcode_op_start_taint=target_call_op,
            originating_imported_func_name_for_log="address_{}".format(target_address),
            current_depth=0,
            initial_tainted_stack_offsets=stack_offsets_to_taint
        )

        # --- Multi-Stage Analysis Driver ---
        processed_tasks = 0
        while analyzer.pending_analysis_tasks:
            processed_tasks += 1
            task = analyzer.pending_analysis_tasks.pop(0)
            task_origin = task.get('originating_imported_func_name_for_log', 'Unknown_Tainted_Return')
            
            analyzer.println("\n--- Initiating Stage 2 Analysis Task #{} (from: {}) ---".format(
                processed_tasks, task_origin
            ))
            
            # The key for visited_function_states includes the origin, so no need to clear it.
            # This allows re-visiting a function if taint comes from a different source.
            analyzer._trace_taint_in_function(
                high_func_to_analyze=task['high_func_to_analyze'],
                initial_tainted_hvs=task['initial_tainted_hvs'],
                pcode_op_start_taint=task['pcode_op_start_taint'],
                originating_imported_func_name_for_log=task_origin,
                current_depth=0, # Start a fresh trace from depth 0
                analysis_config=task.get('analysis_config'),
                tainted_memory_regions=task.get('tainted_memory_regions')
            )
        
        if processed_tasks > 0:
            analyzer.println("\n--- All Multi-Stage Analysis Tasks Complete. ---")
        # --- [END] Multi-Stage Analysis Driver ---

        # Generate the JSON file with tainted comparisons
        analyzer.println("\n--- Analysis Complete. Generating comparison report... ---")
        generate_comparison_json(analyzer)

    except Exception as e:
        import traceback
        _effective_printerr = _printerr if _printerr else lambda msg: sys.stderr.write(str(msg) + "\n")
        _effective_printerr("An unhandled error occurred during AddressAnalyzer execution:")
        _effective_printerr(str(e))
        try:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
            for line in tb_lines:
                _effective_printerr(line.rstrip())
        except Exception as p_e:
            _effective_printerr("Error printing traceback: {}".format(p_e))
    finally:
        if analyzer:
            del analyzer


if __name__ == "__main__":
    if 'currentProgram' in globals() and globals().get('currentProgram') is not None:
        run_analysis_from_ghidra_ui()
    else:
        print("This script is designed to be run from within Ghidra's Script Manager.")
    
    _final_println = globals().get('println', lambda x: None)
    _final_println("Address Taint Analyzer finished.") 