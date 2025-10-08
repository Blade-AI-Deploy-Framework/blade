# analyze_mnn_taint_modular.py
# An MNN-specific taint analysis script that uses the generic taint engine.
# It defines MNN-specific heuristics and injects them into the generic analyzer.

# Ghidra Script Boilerplate
try:
    _current_program = currentProgram
    _current_address = currentAddress
    _monitor = monitor
    _println = println
    _printerr = printerr
    _askFile = askFile
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
    # Add script directory to path to allow importing our modules
    import os
    # Assuming the script is in the same directory as generic_taint_analyzer
    sys.path.append(os.path.dirname(os.path.realpath(__file__)))

from generic_taint_analyzer import TaintAnalyzer

import sys
import json # Added for JSON file generation
import os # To access environment variables and path functions
import re # For cleaning up operand representations

# Attempt to import the generic analyzer.
# This allows the script to be self-contained for simple distribution,
# while still benefiting from a modular structure.
try:
    from generic_taint_analyzer import TaintAnalyzer
except ImportError:
    print("ERROR: Could not find 'generic_taint_analyzer.py'.")
    print("Please ensure it is in the same directory as this script or in Ghidra's script paths.")
    sys.exit(1)


def copy_to_host_tensor_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Heuristic Rule: When a tainted value is passed to `copyToHostTensor`,
    assume the function's return value is tainted and do not recurse into it.
    This is a simplification to handle external library calls where deep analysis fails.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    
    # We only care about CALL operations
    if current_pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
        return False
        
    # Check if the called function is the one we're interested in
    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)
    if not called_function_obj or "copyToHostTensor" not in called_function_obj.getName():
        return False

    # Check if any argument is tainted, as we only want to act on calls in our taint chain
    is_any_arg_tainted = False
    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()):
        arg_vn = current_pcode_op.getInput(pcode_arg_idx)
        if arg_vn:
            arg_hv = arg_vn.getHigh()
            if arg_hv and (arg_hv in tainted_hvs or analyzer._get_varnode_representation(arg_hv, high_func) in tainted_hvs_repr):
                is_any_arg_tainted = True
                break

    if not is_any_arg_tainted:
        return False

    analyzer.println("INFO: [RULE copyToHostTensor] Detected call to '{}' with tainted arguments.".format(called_function_obj.getName()))
    
    # Taint the return value, if it exists
    output_vn = current_pcode_op.getOutput()
    if output_vn:
        output_hv = output_vn.getHigh()
        if output_hv:
            if output_hv not in tainted_hvs:
                tainted_hvs.add(output_hv)
                output_hv_repr = analyzer._get_varnode_representation(output_hv, high_func)
                tainted_hvs_repr.add(output_hv_repr)
                analyzer.println("INFO: [RULE copyToHostTensor] Tainting return value: {}".format(output_hv_repr))
                # Log this as a specific usage type for clarity
                analyzer.all_tainted_usages.append({
                    "originating_imported_function_name": origin_log_name,
                    "function_name": high_func.getFunction().getName(),
                    "function_entry": high_func.getFunction().getEntryPoint().toString(),
                    "address": current_pcode_op.getSeqnum().getTarget().toString(),
                    "pcode_op_str": str(current_pcode_op),
                    "usage_type": "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN",
                    "tainted_component_repr": output_hv_repr,
                    "details": "Return value of host call {} tainted by heuristic rule.".format(called_function_obj.getName())
                })
        else:
            analyzer.println("WARN: [RULE copyToHostTensor] Call has an output varnode but no HighVariable. Cannot taint.")
    else:
        analyzer.println("INFO: [RULE copyToHostTensor] Call has no return value to taint.")

    # Return True to signify we've handled this call and to stop further recursion.
    return True


def mnn_tensor_constructor_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    This rule implements the final, most robust multi-stage analysis logic by recursively
    tracing P-code definitions to find the ultimate stack-relative origin.

    Rule:
    1. Find a tainted call to the `Tensor` constructor.
    2. Identify its `this` pointer.
    3. Recursively trace back the definition of the `this` pointer through COPY and CAST
       operations until the origin `PTRADD(SP, offset)` is found.
    4. Extract the `offset` and calculate the target sink's offset by adding 0x10.
    5. Scan forward in the P-code to find an operation that uses this new sink address.
    6. Queue a new taint analysis task starting from the output of that sink operation.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    
    if current_pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
        return False
        
    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)
    if not called_function_obj or called_function_obj.getName() != "Tensor":
        return False

    is_any_other_arg_tainted = False
    for pcode_arg_idx in range(2, current_pcode_op.getNumInputs()):
        arg_vn = current_pcode_op.getInput(pcode_arg_idx)
        if arg_vn:
            arg_hv = arg_vn.getHigh()
            if arg_hv and (arg_hv in tainted_hvs or analyzer._get_varnode_representation(arg_hv, high_func) in tainted_hvs_repr):
                analyzer.println("INFO: [MNN_RULE] Found call to 'Tensor' with a tainted argument.")
                is_any_other_arg_tainted = True
                break
    
    if not is_any_other_arg_tainted:
        return False

    if current_pcode_op.getNumInputs() < 2: return False
    this_ptr_vn = current_pcode_op.getInput(1)
    
    # 3. Recursively trace back the definition of the `this` pointer.
    MAX_TRACEBACK_DEPTH = 5
    current_vn = this_ptr_vn
    origin_op = None
    
    for i in range(MAX_TRACEBACK_DEPTH):
        def_op = current_vn.getDef()
        if not def_op:
            analyzer.println("WARN: [MNN_RULE] Traceback stopped. Varnode has no defining op: {}".format(current_vn))
            break

        analyzer.println("DEBUG: [MNN_RULE] Tracing `this` pointer... At VN: {}, Def_Op: {}".format(current_vn, def_op))

        if def_op.getMnemonic() in ["PTRADD", "INT_ADD", "PTRSUB"]:
            origin_op = def_op
            break
        elif def_op.getMnemonic() in ["COPY", "CAST"] and def_op.getNumInputs() > 0:
            current_vn = def_op.getInput(0)
            continue
        else:
            analyzer.println("WARN: [MNN_RULE] Traceback stopped. Encountered non-traversable op: {}".format(def_op.getMnemonic()))
            break

    if not origin_op:
        analyzer.println("WARN: [MNN_RULE] Could not find PTRADD/INT_ADD origin for `this` pointer within {} steps.".format(MAX_TRACEBACK_DEPTH))
        return False

    # Check if the found origin is SP-relative, or more generally, register+offset
    op_in0 = origin_op.getInput(0)
    op_in1 = origin_op.getInput(1)
    base_reg_vn = None
    offset_vn = None
    
    if op_in0.isRegister() and op_in1.isConstant():
        base_reg_vn = op_in0
        offset_vn = op_in1
    elif op_in1.isRegister() and op_in0.isConstant():
        base_reg_vn = op_in1
        offset_vn = op_in0
    
    if not base_reg_vn or not offset_vn:
        analyzer.println("WARN: [MNN_RULE] Could not identify a base_register + offset pattern in origin op '{}'".format(origin_op))
        return False

    analyzer.println("DEBUG: [MNN_RULE] Identified base register as {} and offset as {:#x}".format(base_reg_vn, offset_vn.getOffset()))

    # 4. Extract the offset and calculate the target sink's offset.
    # The previous logic for handling PTRSUB was flawed. The decompiler sometimes emits
    # confusing P-code (e.g., PTRSUB with a negative constant). The most robust way
    # is to just trust the signed value of the constant varnode as the effective offset
    # for an addition, as the decompiler seems to model everything as base + offset,
    # sometimes representing the operation as base - (-offset).
    this_ptr_offset = offset_vn.getOffset()
        
    target_sink_offset = this_ptr_offset + 0x10
    analyzer.println("DEBUG: [MNN_RULE] Found base-relative origin. `this` offset is {:#x}. Calculated sink offset: {:#x}".format(this_ptr_offset, target_sink_offset))

    # 5. High-level variable search.
    # The previous approach of matching low-level `LOAD(PTRADD(...))` patterns fails
    # because we are operating on High P-code, where the decompiler has already
    # abstracted stack accesses into stack variables. The correct approach is to
    # leverage this abstraction.

    # 5a. Find the stack variable symbol corresponding to our calculated sink offset.
    local_vars = high_func.getLocalSymbolMap().getSymbols()
    target_hv = None
    for high_sym in local_vars:
        storage = high_sym.getStorage()
        # The storage can be a stack, register, or memory address.
        # We need to check if it's stack storage and if the offset matches.
        if storage.isStackStorage() and storage.getStackOffset() == target_sink_offset:
            target_hv = high_sym.getHighVariable()
            analyzer.println("DEBUG: [MNN_RULE] Found matching stack symbol '{}' at offset {:#x}.".format(high_sym.getName(), target_sink_offset))
            break
    
    if not target_hv:
        analyzer.printerr("ERROR: [MNN_RULE] Calculated sink offset {:#x}, but could not find a corresponding local stack variable.".format(target_sink_offset))
        return True

    # 5b. Scan forward from the constructor call to find the first USE of this stack variable.
    # In High P-code, this will typically be a COPY operation.
    for forward_idx in range(op_idx + 1, len(all_pcode_ops)):
        forward_op = all_pcode_ops[forward_idx]
        
        # --- [USER DEBUG] Print each p-code op being checked ---
        analyzer.println("DEBUG: [MNN_RULE_SCAN] Checking P-code at index {}: {}".format(forward_idx, forward_op))
        # --- [END USER DEBUG] ---

        if forward_op.getMnemonic() == "COPY":
            # Check if the input to the copy is our target high variable
            if forward_op.getNumInputs() > 0 and forward_op.getInput(0).getHigh() == target_hv:
                sink_vn = forward_op.getOutput()
                sink_hv = sink_vn.getHigh() if sink_vn else None

                if not sink_hv:
                    analyzer.printerr("ERROR: [MNN_RULE] Found sink COPY op but could not get HighVariable for its output. Cannot continue taint.")
                    return True # Stop processing

                sink_address = forward_op.getSeqnum().getTarget().toString()
                sink_hv_repr = analyzer._get_varnode_representation(sink_hv, high_func)

                analyzer.println("INFO: [MNN_RULE] Found sink use via COPY operation at address {}: {}. Tainting its output: {}".format(
                    sink_address,
                    forward_op, 
                    sink_hv_repr
                ))

                # MODIFIED LOGIC: Instead of queuing a new, separate analysis task,
                # this rule will now directly add the sink to the current analysis context.
                # This aligns with the user's suggestion to "just add it to the taint set"
                # and matches the behavior of other rules.
                if sink_hv not in tainted_hvs:
                    tainted_hvs.add(sink_hv)
                    tainted_hvs_repr.add(sink_hv_repr)
                    analyzer.println("INFO: [MNN_RULE] Added {} to current taint set.".format(sink_hv_repr))
                    # Log this usage as a specific type for clarity
                    analyzer.all_tainted_usages.append({
                        "originating_imported_function_name": origin_log_name,
                        "function_name": high_func.getFunction().getName(),
                        "function_entry": high_func.getFunction().getEntryPoint().toString(),
                        "address": sink_address,
                        "pcode_op_str": str(forward_op),
                        "usage_type": "TAINT_PROPAGATED_FROM_CONSTRUCTOR_SINK",
                        "tainted_component_repr": sink_hv_repr,
                        "details": "Sink from constructor side-effect at {} tainted by MNN rule.".format(sink_address)
                    })

                return True # Rule has fired. Stop searching.

    analyzer.printerr("ERROR: [MNN_RULE] Found stack variable for sink, but could not find a subsequent COPY operation using it.")
    return True

def generate_hook_config(analyzer):
    """
    Generates a JSON configuration file for hooking based on tainted branch conditions.
    This version uses the raw, unprocessed data from the taint analyzer.
    """
    if not analyzer.all_tainted_usages:
        analyzer.println("No tainted usages found, skipping hook config generation.")
        return

    hook_entries = []
    processed_addresses = set()

    for usage in analyzer.all_tainted_usages:
        if usage.get("usage_type") == "BRANCH_CONDITION_TAINTED":
            address_str = usage.get("address", "N/A")
            
            # Skip if address is invalid or already processed
            if address_str == "N/A" or address_str in processed_addresses:
                continue
            processed_addresses.add(address_str)

            # --- New logic: Find preceding comparison instruction and its properties ---
            branch_target_str = "N/A"
            comparison_instruction_obj = None
            comparison_address_str = "N/A"
            comparison_instruction_str = "N/A"

            try:
                addr_factory = analyzer.current_program.getAddressFactory()
                branch_addr = addr_factory.getAddress(address_str)
                branch_instruction = analyzer.current_program.getListing().getInstructionAt(branch_addr)

                if branch_instruction:
                    # Search backwards for a comparison instruction that sets the flags
                    prev_instr = branch_instruction
                    for _ in range(10): # Search up to 10 instructions back
                        prev_instr = prev_instr.getPrevious()
                        if not prev_instr:
                            break
                        
                        mnemonic = prev_instr.getMnemonicString().lower()
                        # Common ARM comparison instructions (integer and float) that set flags
                        if mnemonic in ['cmp', 'tst', 'cmn', 'teq', 'fcmp', 'fcmpe', 'ucmp', 'subs', 'adds', 'ands']:
                            comparison_instruction_obj = prev_instr
                            # Get address without memory space prefix, e.g., "ram:001021ac" -> "001021ac"
                            comparison_address_str = comparison_instruction_obj.getAddress().toString().split(":")[-1]
                            comparison_instruction_str = comparison_instruction_obj.toString() # e.g., "cmp w8, w9"
                            analyzer.println("INFO: Found preceding comparison instruction '{}' at {} for branch at {}".format(
                                comparison_instruction_str, comparison_address_str, address_str
                            ))
                            break
                    
                    if not comparison_instruction_obj:
                        analyzer.printerr("WARN: Could not find preceding comparison instruction for branch at {}. Skipping.".format(address_str))
                        continue

                    # --- Get branch target (from original branch instruction) ---
                    fallthrough_addr = branch_instruction.getFallThrough()
                    flows = branch_instruction.getFlows()
                    target_addr = None
                    if flows and len(flows) > 0:
                        for flow_addr in flows:
                            if fallthrough_addr is None or not flow_addr.equals(fallthrough_addr):
                                target_addr = flow_addr
                                break
                    if target_addr:
                        target_addr_val = target_addr.getOffset()
                        modified_target_addr_val = target_addr_val - 0x100000
                        branch_target_str = "0x{:x}".format(modified_target_addr_val)
                    else:
                        analyzer.printerr("WARN: Could not determine branch target for instruction at '{}'".format(address_str))
                else:
                    analyzer.printerr("WARN: Could not find instruction at address '{}' to get branch target".format(address_str))
                    continue
            except Exception as e:
                analyzer.printerr("ERROR: Exception while processing branch at {}: {}".format(address_str, e))
                continue

            # Modify address: subtract 0x100000 and format with '0x'
            try:
                # Use the address of the comparison instruction
                addr_val = int(comparison_address_str, 16)
                modified_addr_val = addr_val - 0x100000
                modified_address_str = "0x{:x}".format(modified_addr_val)
            except ValueError:
                analyzer.printerr("WARN: Could not parse comparison address '{}' for hook config. Skipping.".format(comparison_address_str))
                continue

            # --- Also format original branch address for new field ---
            try:
                branch_addr_val = int(address_str, 16)
                modified_branch_addr_val = branch_addr_val - 0x100000
                modified_branch_address_str = "0x{:x}".format(modified_branch_addr_val)
            except ValueError:
                modified_branch_address_str = "N/A"

            
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
                # We use the cleanup function to ensure consistency, as was done in the previous version's fallback.
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
                "original_branch_instruction": branch_instruction.getMnemonicString()
            }
            hook_entries.append(entry)

    # --- Output File Logic ---
    script_dir = os.path.dirname(os.path.realpath(__file__))
    results_dir = os.path.join(script_dir, "results")
    
    if not os.path.exists(results_dir):
        try:
            os.makedirs(results_dir)
        except OSError: # Keep it simple
            pass

    program_name = analyzer.current_program.getName()
    output_filename = "{}_hook_config.json".format(program_name) # Revert to the original desired name
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
# Main script entry point (Ghidra script boilerplate)
# -------------------
def run_analysis_from_ghidra_ui():
    """
    This function is the main entry point when run from Ghidra's UI.
    It sets up the environment and kicks off the analysis.
    """
    if not all((_current_program, _monitor, _println, _printerr, _askFile)):
        sys.stderr.write("Error: This script must be run within a full Ghidra UI environment.\n")
        return

    analyzer = None
    try:
        # Register the MNN-specific rule handler with the generic analyzer.
        mnn_rules = [copy_to_host_tensor_rule_handler, mnn_tensor_constructor_rule_handler]

        analyzer = TaintAnalyzer(
            current_program=_current_program,
            monitor=_monitor,
            println=_println,
            printerr=_printerr,
            askFile=_askFile,
            rule_handlers=mnn_rules
        )
        target_api_keyword = "getSessionOutput"
        analyzer.run([target_api_keyword])

        # After the main analysis, generate the specialized hook config
        generate_hook_config(analyzer)

    except Exception as e:
        import traceback
        _effective_printerr = _printerr if _printerr else lambda msg: sys.stderr.write(str(msg) + "\n")
        _effective_printerr("An unhandled error occurred during TaintAnalyzer setup or execution:")
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
    _final_println("MNN Taint Analyzer finished.") 