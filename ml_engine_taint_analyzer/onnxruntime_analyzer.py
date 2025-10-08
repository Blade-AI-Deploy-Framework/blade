try :
    _current_program =currentProgram 
    _current_address =currentAddress 
    _monitor =monitor 
    _println =println 
    _printerr =printerr 
    _askFile =askFile 
except NameError :
    import sys 
    _current_program =None 
    _current_address =None 
    _monitor =None 
    _println =lambda msg :sys .stdout .write (str (msg )+"\n")
    _printerr =lambda msg :sys .stderr .write (str (msg )+"\n")
    _askFile =None 
    import os 
    sys .path .append (os .path .dirname (os .path .realpath (__file__ )))

import sys 
import json 
import os 

try :
    from generic_taint_analyzer import TaintAnalyzer 
except ImportError :
    print ("ERROR: Could not find 'generic_taint_analyzer.py'.")
    print ("Please ensure it is in the same directory as this script or in Ghidra's script paths.")
    sys .exit (1 )

def onnxruntime_api_call_rule_handler (analyzer ,op_idx ,all_pcode_ops ,high_func ,tainted_hvs ,tainted_hvs_repr ,origin_log_name ):
    """
    Heuristic for ONNXRuntime C API calls via the global API struct.
    This rule identifies indirect calls that retrieve the model's output tensor data
    (e.g., GetTensorMutableData) and taints the returned data pointer.
    """
    current_pcode_op =all_pcode_ops [op_idx ]

    if current_pcode_op .getMnemonic ()!="CALLIND":
        return False 

    call_target_vn =current_pcode_op .getInput (0 )
    is_from_ort_api =False 

    try :
        def_op =call_target_vn .getDef ()
        if def_op and def_op .getMnemonic ()=="LOAD":
            addr_vn =def_op .getInput (1 )
            addr_def_op =addr_vn .getDef ()
            if addr_def_op and addr_def_op .getMnemonic ()in ["PTRADD","INT_ADD"]:
                base_vn =addr_def_op .getInput (0 )
                offset_vn =addr_def_op .getInput (1 )

                if not offset_vn .isConstant ():
                    base_vn ,offset_vn =offset_vn ,base_vn 

                if offset_vn .isConstant ():
                    base_def_op =base_vn .getDef ()
                    if base_def_op and base_def_op .getMnemonic ()=="LOAD":
                        global_addr_vn =base_def_op .getInput (1 )
                        if global_addr_vn .isConstant ():
                            addr =analyzer .current_program .getAddressFactory ().getDefaultAddressSpace ().getAddress (global_addr_vn .getOffset ())
                            sym =analyzer .current_program .getSymbolTable ().getPrimarySymbol (addr )
                            if sym and "Ort"in sym .getName ()and "Api"in sym .getName ():
                                is_from_ort_api =True 
    except Exception :

        return False 

    if not is_from_ort_api :
        return False 

    analyzer .println ("INFO: [ONNXRUNTIME_API_RULE] Detected a CALLIND from the OrtApi struct at {}.".format (current_pcode_op .getSeqnum ().getTarget ()))

    if current_pcode_op .getNumInputs ()<3 :
        return False 

    output_ptr_arg_vn =current_pcode_op .getInput (2 )
    if not output_ptr_arg_vn or not output_ptr_arg_vn .getHigh ():
        return False 

    MAX_FORWARD_SCAN_OPS =25 
    for forward_idx in range (op_idx +1 ,min (op_idx +1 +MAX_FORWARD_SCAN_OPS ,len (all_pcode_ops ))):
        forward_op =all_pcode_ops [forward_idx ]

        if forward_op .getMnemonic ()!="LOAD":
            continue 

        load_addr_vn =forward_op .getInput (1 )

        if analyzer ._is_varnode_derived_from (load_addr_vn ,output_ptr_arg_vn .getHigh (),high_func ):
            tensor_data_ptr_vn =forward_op .getOutput ()
            if not tensor_data_ptr_vn :continue 

            tensor_data_ptr_hv =tensor_data_ptr_vn .getHigh ()
            if not tensor_data_ptr_hv or tensor_data_ptr_hv in tainted_hvs :continue 

            tainted_hvs .add (tensor_data_ptr_hv )
            tensor_data_ptr_hv_repr =analyzer ._get_varnode_representation (tensor_data_ptr_hv ,high_func )
            tainted_hvs_repr .add (tensor_data_ptr_hv_repr )

            analyzer .println ("INFO: [ONNXRUNTIME_API_RULE] Tainted new Tensor data pointer {} at {}.".format (
            tensor_data_ptr_hv_repr ,
            forward_op .getSeqnum ().getTarget ().toString ()
            ))

            analyzer .all_tainted_usages .append ({
            "originating_imported_function_name":"OrtApi::GetTensorMutableData",
            "function_name":high_func .getFunction ().getName (),
            "function_entry":high_func .getFunction ().getEntryPoint ().toString (),
            "address":forward_op .getSeqnum ().getTarget ().toString (),
            "pcode_op_str":str (forward_op ),
            "usage_type":"TAINT_SOURCE_FROM_API_CALL",
            "tainted_component_repr":tensor_data_ptr_hv_repr ,
            "details":"Tensor data pointer at {} tainted by OrtApi rule.".format (tensor_data_ptr_hv_repr )
            })

            return True 

    analyzer .println ("WARN: [ONNXRUNTIME_API_RULE] Failed to find LOAD from output pointer after OrtApi call.")
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

def run_analysis_from_ghidra_ui ():
    """
    Main entry point when run from Ghidra's UI.
    """
    if not all ((_current_program ,_monitor ,_println ,_printerr )):
        sys .stderr .write ("Error: This script must be run within a Ghidra environment.\n")
        return 

    analyzer =None 
    try :

        onnx_rules =[onnxruntime_api_call_rule_handler ]

        analyzer =TaintAnalyzer (
        current_program =_current_program ,
        monitor =_monitor ,
        println =_println ,
        printerr =_printerr ,
        askFile =_askFile ,
        rule_handlers =onnx_rules 
        )

        target_api_keywords =["GetTensorData"]
        analyzer .run (target_api_keywords )

        generate_hook_config (analyzer )

    except Exception as e :
        import traceback 
        _printerr ("An unhandled error occurred during TaintAnalyzer execution:")
        _printerr (str (e ))
        traceback .print_exc (file =sys .stderr )
    finally :
        if analyzer :
            del analyzer 

if __name__ =="__main__":
    if 'currentProgram'in globals ()and globals ().get ('currentProgram')is not None :
        run_analysis_from_ghidra_ui ()
    else :
        print ("This script is designed to be run from within Ghidra's Script Manager.")

    _final_println =globals ().get ('println',lambda x :None )
    _final_println ("ONNXRuntime Taint Analyzer finished.")