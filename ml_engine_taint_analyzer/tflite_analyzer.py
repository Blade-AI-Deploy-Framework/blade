# tflite_analyzer.py
# A TFLite-specific taint analysis script that uses the generic taint engine.
# It defines TFLite-specific heuristics and injects them into the generic analyzer.

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


def tflite_builder_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Heuristic for TFLite Interpreter creation. This rule acts as a taint source.
    It finds calls to InterpreterBuilder::operator() and taints the created Interpreter object,
    which is passed back via a pointer argument rather than a direct return value.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    
    # 1. Trigger: We only care about CALL operations to InterpreterBuilder::operator()
    if current_pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
        return False
        
    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)
    
    if not called_function_obj:
        return False
    called_func_name = called_function_obj.getName()

    # We need a very specific match here
    if "InterpreterBuilder" not in called_func_name or "operator" not in called_func_name:
        return False

    analyzer.println("INFO: [TFLITE_BUILDER_RULE] Detected call to '{}'.".format(called_func_name))

    # 2. Condition: The result is returned via the second argument (input(2) in p-code).
    # This argument is a pointer to a location where the result unique_ptr will be stored.
    if current_pcode_op.getNumInputs() < 3:
        analyzer.println("WARN: [TFLITE_BUILDER_RULE] Call to {} has fewer than 2 arguments. Cannot find output pointer.".format(called_func_name))
        return False # Not the call we are looking for

    # P-code input(0) is call target address, input(1) is 'this', input(2) is the output pointer argument.
    output_ptr_arg_vn = current_pcode_op.getInput(2)

    # 3. Action: Scan forward to find where the interpreter pointer is LOADed from the memory
    # location pointed to by our output argument.
    MAX_FORWARD_SCAN_OPS = 25
    for forward_idx in range(op_idx + 1, min(op_idx + 1 + MAX_FORWARD_SCAN_OPS, len(all_pcode_ops))):
        forward_op = all_pcode_ops[forward_idx]

        if forward_op.getMnemonic() != "LOAD":
            continue

        load_addr_vn = forward_op.getInput(1)

        # Check if the address used in the LOAD is derived from our output argument.
        if analyzer._is_varnode_derived_from(load_addr_vn, output_ptr_arg_vn.getHigh(), high_func):
            interpreter_ptr_vn = forward_op.getOutput()
            if not interpreter_ptr_vn:
                continue
            
            interpreter_ptr_hv = interpreter_ptr_vn.getHigh()
            if not interpreter_ptr_hv or interpreter_ptr_hv in tainted_hvs:
                # Found it. Taint the interpreter pointer.
                tainted_hvs.add(interpreter_ptr_hv)
                interpreter_ptr_hv_repr = analyzer._get_varnode_representation(interpreter_ptr_hv, high_func)
                tainted_hvs_repr.add(interpreter_ptr_hv_repr)
                
                analyzer.println("INFO: [TFLITE_BUILDER_RULE] Tainted new Interpreter pointer {} at {}.".format(
                    interpreter_ptr_hv_repr,
                    forward_op.getSeqnum().getTarget().toString()
                ))

                analyzer.all_tainted_usages.append({
                    "originating_imported_function_name": called_func_name, # Use the function name as origin
                    "function_name": high_func.getFunction().getName(),
                    "function_entry": high_func.getFunction().getEntryPoint().toString(),
                    "address": forward_op.getSeqnum().getTarget().toString(),
                    "pcode_op_str": str(forward_op),
                    "usage_type": "TAINT_SOURCE_FROM_BUILDER",
                    "tainted_component_repr": interpreter_ptr_hv_repr,
                    "details": "Interpreter pointer at {} tainted by TFLite Builder rule.".format(interpreter_ptr_hv_repr)
                })
                
                return True # This rule's job is done for this call.

    analyzer.println("WARN: [TFLITE_BUILDER_RULE] Failed to find LOAD from output pointer after {} call.".format(called_func_name))
    return True # Prevent recursion anyway


def tflite_invoke_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Heuristic Rule for TFLite: When a tainted Interpreter object calls Invoke(),
    scan forward to find the code that accesses the output tensor data and taint it.
    This is based on the common pattern where the output tensor data is accessed
    shortly after the Invoke() call returns.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    
    # 1. Trigger: We only care about CALL operations to Interpreter::Invoke
    if current_pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
        return False
        
    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)
    
    # Check for a more flexible name, as demangling can produce different results
    # (e.g., with/without templates, different spacing, etc.)
    if not called_function_obj:
        return False
    called_func_name = called_function_obj.getName()
    if "Interpreter" not in called_func_name or "Invoke" not in called_func_name:
        return False

    # 2. Condition: The 'this' pointer (the interpreter object) must be tainted.
    # The 'this' pointer is the first argument to the method call in P-code (input 1).
    if current_pcode_op.getNumInputs() < 2:
        return False
    
    this_ptr_vn = current_pcode_op.getInput(1)
    this_ptr_hv = this_ptr_vn.getHigh()
    
    if not this_ptr_hv or not (this_ptr_hv in tainted_hvs or analyzer._get_varnode_representation(this_ptr_hv, high_func) in tainted_hvs_repr):
        return False

    analyzer.println("INFO: [TFLITE_RULE] Detected call to '{}' with a tainted interpreter object.".format(called_function_obj.getName()))

    # 3. Action: Scan forward from the Invoke() call to find the output tensor access.
    # The pattern we look for is a LOAD from a pointer that is derived from the interpreter object.
    # This is a heuristic, as the exact chain of P-code ops can vary.
    # We will look for a LOAD whose result is subsequently used in a loop or comparison,
    # as this is typical for post-processing model outputs.
    
    MAX_FORWARD_SCAN_OPS = 50  # Search within a reasonable window after Invoke()
    for forward_idx in range(op_idx + 1, min(op_idx + 1 + MAX_FORWARD_SCAN_OPS, len(all_pcode_ops))):
        forward_op = all_pcode_ops[forward_idx]

        # We are looking for a LOAD operation.
        if forward_op.getMnemonic() != "LOAD":
            continue

        load_ptr_vn = forward_op.getInput(1) # Pointer used in the LOAD
        
        # Check if this pointer is derived from our tainted interpreter object.
        # This helper function recursively traces the definition of a varnode.
        if analyzer._is_varnode_derived_from(load_ptr_vn, this_ptr_hv, high_func):
            output_data_vn = forward_op.getOutput()
            if not output_data_vn:
                continue
            
            output_data_hv = output_data_vn.getHigh()
            if not output_data_hv:
                continue

            # We found a variable that is loaded from a memory location related to the interpreter.
            # This is a strong candidate for the output tensor data pointer. Taint it.
            if output_data_hv not in tainted_hvs:
                tainted_hvs.add(output_data_hv)
                output_data_hv_repr = analyzer._get_varnode_representation(output_data_hv, high_func)
                tainted_hvs_repr.add(output_data_hv_repr)
                
                analyzer.println("INFO: [TFLITE_RULE] Found candidate output tensor data at {}: {}. Tainting it.".format(
                    forward_op.getSeqnum().getTarget().toString(),
                    output_data_hv_repr
                ))
                
                # Log this discovery
                analyzer.all_tainted_usages.append({
                    "originating_imported_function_name": origin_log_name,
                    "function_name": high_func.getFunction().getName(),
                    "function_entry": high_func.getFunction().getEntryPoint().toString(),
                    "address": forward_op.getSeqnum().getTarget().toString(),
                    "pcode_op_str": str(forward_op),
                    "usage_type": "TAINT_PROPAGATED_FROM_INVOKE_OUTPUT",
                    "tainted_component_repr": output_data_hv_repr,
                    "details": "Output tensor data pointer at {} tainted by TFLite Invoke() rule.".format(output_data_hv_repr)
                })

                # We have found and tainted our target. Stop this rule's execution for this Invoke call.
                # Returning True also tells the main analyzer to not recurse into Invoke itself.
                return True

    analyzer.println("WARN: [TFLITE_RULE] Call to Invoke() was found, but failed to identify a subsequent output tensor access within the search window.")
    # Return True to prevent recursion into Invoke, as we assume we've handled it.
    return True


def generate_hook_config(analyzer):
    """
    Generates a JSON configuration file for hooking based on tainted branch conditions.
    This function is generic and can be reused from the mnn_analyzer.
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

            # --- MODIFIED LOGIC: Use high-level P-code representations from analysis results ---
            registers_with_taint_info = []
            
            # The 'compared_ops_repr' field in the usage log already contains the high-level
            # variable representations as determined by the taint analyzer.
            # We will use this directly instead of re-parsing the assembly instruction to get
            # the desired high-level IR form (e.g., bVar1, UNNAMED, etc.).
            raw_high_level_vars = usage.get("compared_ops_repr", [])
            
            if not raw_high_level_vars:
                analyzer.printerr("WARN: No high-level operand representations found in usage log for branch at {}. 'registers' field will be empty.".format(address_str))

            for var_repr in raw_high_level_vars:
                # The representation is already in the desired high-level format, e.g., "bVar1(UniquePcode[...])"
                # We use the cleanup function to ensure consistency.
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
    """
    if not all((_current_program, _monitor, _println, _printerr)):
        sys.stderr.write("Error: This script must be run within a Ghidra environment.\n")
        return

    analyzer = None
    try:
        # Register the TFLite-specific rule handler.
        tflite_rules = [tflite_builder_rule_handler, tflite_invoke_rule_handler]

        analyzer = TaintAnalyzer(
            current_program=_current_program,
            monitor=_monitor,
            println=_println,
            printerr=_printerr,
            askFile=_askFile, # Can be None if not in UI
            rule_handlers=tflite_rules
        )
        
        # The starting point for TFLite analysis. We taint the result of building the model
        # or allocating tensors, which in turn taints the interpreter object itself.
        # A good generic starting point is the function that builds the interpreter.
        # Use a more generic keyword for the initial search, as demangled names can vary.
        # The rule handler will perform a more specific check.
        target_api_keyword = "operator"
        analyzer.run([target_api_keyword])

        # After analysis, generate the hook config from any tainted branches found.
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
    _final_println("TFLite Taint Analyzer finished.")
