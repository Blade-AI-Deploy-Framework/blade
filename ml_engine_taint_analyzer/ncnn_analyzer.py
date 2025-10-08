# ncnn_analyzer.py
# An NCNN-specific taint analysis script that uses the generic taint engine.
# It defines NCNN-specific heuristics and injects them into the generic analyzer.

# Ghidra Script Boilerplate
try:
    _current_program = currentProgram
    _current_address = currentAddress
    _monitor = monitor
    _println = println
    _printerr = printerr
    _askFile = askFile
except NameError:
    import sys
    _current_program = None
    _current_address = None
    _monitor = None
    _println = lambda msg: sys.stdout.write(str(msg) + "\n")
    _printerr = lambda msg: sys.stderr.write(str(msg) + "\n")
    _askFile = None
    import os
    sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import sys
import json
import os

# Attempt to import the generic analyzer.
try:
    from generic_taint_analyzer import TaintAnalyzer
except ImportError:
    print("ERROR: Could not find 'generic_taint_analyzer.py'.")
    print("Please ensure it is in the same directory as this script or in Ghidra's script paths.")
    sys.exit(1)


def generate_hook_config(analyzer):
    """
    Generates a JSON configuration file for hooking based on tainted branch conditions.
    This function is generic and copied from other analyzers.
    """
    if not analyzer.all_tainted_usages:
        analyzer.println("No tainted usages found, skipping hook config generation.")
        return

    hook_entries = []
    processed_addresses = set()

    for usage in analyzer.all_tainted_usages:
        if usage.get("usage_type") == "BRANCH_CONDITION_TAINTED":
            address_str = usage.get("address", "N/A")
            
            if address_str == "N/A" or address_str in processed_addresses:
                continue
            processed_addresses.add(address_str)

            branch_target_str = "N/A"
            comparison_instruction_obj = None
            comparison_address_str = "N/A"
            comparison_instruction_str = "N/A"
            branch_instruction = None

            try:
                addr_factory = analyzer.current_program.getAddressFactory()
                branch_addr = addr_factory.getAddress(address_str)
                branch_instruction = analyzer.current_program.getListing().getInstructionAt(branch_addr)

                if branch_instruction:
                    prev_instr = branch_instruction
                    for _ in range(10): 
                        prev_instr = prev_instr.getPrevious()
                        if not prev_instr: break
                        
                        mnemonic = prev_instr.getMnemonicString().lower()
                        if mnemonic in ['cmp', 'tst', 'cmn', 'teq', 'fcmp', 'fcmpe', 'ucmp', 'subs', 'adds', 'ands']:
                            comparison_instruction_obj = prev_instr
                            comparison_address_str = comparison_instruction_obj.getAddress().toString().split(":")[-1]
                            comparison_instruction_str = comparison_instruction_obj.toString()
                            break
                    
                    if not comparison_instruction_obj:
                        analyzer.printerr("WARN: Could not find preceding comparison for branch at {}.".format(address_str))
                        continue

                    fallthrough_addr = branch_instruction.getFallThrough()
                    flows = branch_instruction.getFlows()
                    target_addr = next((f for f in flows if fallthrough_addr is None or not f.equals(fallthrough_addr)), None)
                    
                    if target_addr:
                        target_addr_val = target_addr.getOffset()
                        modified_target_addr_val = target_addr_val - 0x100000
                        branch_target_str = "0x{:x}".format(modified_target_addr_val)
                    else:
                        analyzer.printerr("WARN: Could not determine branch target at '{}'".format(address_str))
                else:
                    analyzer.printerr("WARN: Could not find instruction at address '{}'".format(address_str))
                    continue
            except Exception as e:
                analyzer.printerr("ERROR: Exception processing branch at {}: {}".format(address_str, e))
                continue

            try:
                addr_val = int(comparison_address_str, 16)
                modified_addr_val = addr_val - 0x100000
                modified_address_str = "0x{:x}".format(modified_addr_val)
            except ValueError:
                analyzer.printerr("WARN: Could not parse comparison address '{}'.".format(comparison_address_str))
                continue

            modified_branch_address_str = "N/A"
            if branch_instruction:
                try:
                    branch_addr_val = int(address_str, 16)
                    modified_branch_addr_val = branch_addr_val - 0x100000
                    modified_branch_address_str = "0x{:x}".format(modified_branch_addr_val)
                except ValueError:
                    pass

            registers_with_taint_info = []
            raw_high_level_vars = usage.get("compared_ops_repr", [])
            
            if not raw_high_level_vars:
                analyzer.printerr("WARN: No high-level operand representations found in usage log for branch at {}. 'registers' field will be empty.".format(address_str))

            for var_repr in raw_high_level_vars:
                cleaned_var = analyzer.cleanup_operand_repr(var_repr)
                registers_with_taint_info.append({
                    "register": cleaned_var
                })
            
            entry = {
                "address": modified_address_str,
                "instruction": comparison_instruction_str,
                "registers": registers_with_taint_info,
                "branch_target": branch_target_str,
                "original_branch_address": modified_branch_address_str,
                "original_branch_instruction": branch_instruction.getMnemonicString() if branch_instruction else "N/A"
            }
            hook_entries.append(entry)

    script_dir = os.path.dirname(os.path.realpath(__file__))
    results_dir = os.path.join(script_dir, "results")
    
    if not os.path.exists(results_dir):
        try: os.makedirs(results_dir)
        except OSError: pass

    program_name = analyzer.current_program.getName()
    output_filename = "{}_hook_config.json".format(program_name)
    output_file_path = os.path.join(results_dir, output_filename)

    if not hook_entries:
        analyzer.println("No tainted branch conditions found to generate a hook config.")
        return

    try:
        with open(output_file_path, 'w') as f:
            json.dump(hook_entries, f, indent=4)
        analyzer.println("SUCCESS: Hook configuration saved to: {}".format(output_file_path))
    except Exception as e:
        analyzer.printerr("ERROR: Could not write hook config to file {}: {}".format(output_file_path, e))


# -------------------
# Main script entry point
# -------------------
def run_analysis_from_ghidra_ui():
    """
    Main entry point when run from Ghidra's UI.
    This version manually finds call sites to the target API and taints
    an output parameter, similar to library_analyzer.py.
    """
    if not all((_current_program, _monitor, _println, _printerr)):
        sys.stderr.write("Error: This script must be run within a Ghidra environment.\n")
        return

    analyzer = None
    try:
        # We are not using rule handlers for this analyzer; the logic is in the main loop.
        analyzer = TaintAnalyzer(
            current_program=_current_program,
            monitor=_monitor,
            println=_println,
            printerr=_printerr,
            askFile=_askFile,
            rule_handlers=[] # No rule handlers needed, logic is custom below
        )
        
        target_api_keyword = "extract"
        _println("INFO: Searching for call sites to functions containing '{}'".format(target_api_keyword))

        func_manager = _current_program.getFunctionManager()
        ref_manager = _current_program.getReferenceManager()

        # 1. Find all functions that could be our target
        target_funcs = set()
        for func in func_manager.getFunctions(True): # True means iterate forward
            if target_api_keyword in func.getName():
                target_funcs.add(func)
                # Also consider thunked functions
                thunked_func = func.getThunkedFunction(True)
                if thunked_func:
                    target_funcs.add(thunked_func)

        if not target_funcs:
            _printerr("ERROR: Could not find any functions matching keyword '{}'".format(target_api_keyword))
            return

        _println("INFO: Found target functions: {}".format([f.getName() for f in target_funcs]))

        # 2. Find all call sites to these functions
        from collections import defaultdict
        call_sites_by_function = defaultdict(list)
        for target_func in target_funcs:
            refs = ref_manager.getReferencesTo(target_func.getEntryPoint())
            for ref in refs:
                if ref.getReferenceType().isCall():
                    containing_func = func_manager.getFunctionContaining(ref.getFromAddress())
                    if containing_func and not containing_func.equals(target_func):
                        call_sites_by_function[containing_func].append(ref.getFromAddress())
        
        if not call_sites_by_function:
            _println("INFO: No call sites found for the target functions.")
            return

        _println("INFO: Found {} unique functions containing call sites. Analyzing each...".format(len(call_sites_by_function)))

        # 3. Analyze each call site
        for parent_func, call_site_addrs in call_sites_by_function.items():
            _println("\n--- Analyzing Function '{}' at {} containing {} call site(s) ---".format(parent_func.getName(), parent_func.getEntryPoint(), len(call_site_addrs)))
            
            decompile_results = analyzer.decompiler.decompileFunction(parent_func, 60, analyzer.monitor)
            if not decompile_results or not decompile_results.getHighFunction():
                _printerr("ERROR: Failed to decompile parent function '{}'. Skipping.".format(parent_func.getName()))
                continue
            
            high_parent_func = decompile_results.getHighFunction()

            for call_site_addr in call_site_addrs:
                _println("\n  -- Analyzing Call Site at {} --".format(call_site_addr))
                
                target_call_op = None
                op_iter = high_parent_func.getPcodeOps(call_site_addr)
                while op_iter.hasNext():
                    pcode_op = op_iter.next()
                    if pcode_op.getMnemonic() in ["CALL", "CALLIND"]:
                        target_call_op = pcode_op
                        break
                
                if not target_call_op:
                    _printerr("ERROR: Could not find CALL p-code op at {}. Skipping site.".format(call_site_addr))
                    continue

                # The output parameter is the 3rd argument (p-code input index 3)
                if target_call_op.getNumInputs() < 4:
                    _println("WARN: Call at {} has too few parameters. Skipping taint.".format(call_site_addr))
                    continue

                output_param_vn = target_call_op.getInput(3)
                if not output_param_vn:
                    _println("WARN: Could not get output parameter varnode at {}. Skipping site.".format(call_site_addr))
                    continue
                
                output_param_hv = output_param_vn.getHigh()
                if not output_param_hv:
                    _println("WARN: Output parameter at {} has no HighVariable. Cannot taint. Skipping site.".format(call_site_addr))
                    continue
                
                # 4. Start the taint trace from this parameter
                initial_taint_set = {output_param_hv}
                _println("INFO: Tainting output parameter from call at {}: {}".format(
                    call_site_addr, analyzer._get_varnode_representation(output_param_hv, high_parent_func)
                ))

                called_function_obj = analyzer._get_called_function_from_pcode_op(target_call_op)
                api_full_name = called_function_obj.getName() if called_function_obj else target_api_keyword

                analyzer._trace_taint_in_function(
                    high_func_to_analyze=high_parent_func,
                    initial_tainted_hvs=initial_taint_set,
                    pcode_op_start_taint=target_call_op,
                    originating_imported_func_name_for_log=api_full_name,
                    current_depth=0,
                    initial_tainted_stack_offsets=set(),
                    tainted_memory_regions=set()
                )

        _println("\n--- All Functions Analyzed. Finalizing Report. ---")
        analyzer._print_results()
        generate_hook_config(analyzer)

    except Exception as e:
        import traceback
        _printerr("An unhandled error occurred during TaintAnalyzer execution:")
        _printerr(str(e))
        traceback.print_exc(file=sys.stderr)
    finally:
        if analyzer:
            del analyzer

if __name__ == "__main__":
    if 'currentProgram' in globals() and globals().get('currentProgram') is not None:
        run_analysis_from_ghidra_ui()
    else:
        print("This script is designed to be run from within Ghidra's Script Manager.")
    
    _final_println = globals().get('println', lambda x: None)
    _final_println("NCNN Taint Analyzer finished.")
