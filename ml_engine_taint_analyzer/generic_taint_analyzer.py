# -*- coding: utf-8 -*-
# analyze_mnn_taint_modular.py
# Modularized version of the taint analysis script.
# Analyzes taint propagation starting from the return value of calls to functions
# matching a specific keyword (e.g., 'getSessionOutput').

# Import necessary Ghidra modules
from ghidra.program.model.pcode import PcodeOp, Varnode, HighVariable
from ghidra.program.model.listing import Function, Instruction, VariableStorage
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import Pointer
import ghidra.program.model.pcode
import traceback
import sys
import json
import os
import re

# A list of common math functions that propagate taint from input to output.
# If an input is tainted, the output should be tainted without recursion.
_MATH_LIB_FUNCTIONS = {
    "exp", "expf", "expm1", "expm1f",
    "log", "logf", "log10", "log10f", "log1p", "log1pf", "log2", "log2f",
    "sin", "sinf", "cos", "cosf", "tan", "tanf",
    "asin", "asinf", "acos", "acosf", "atan", "atanf", "atan2", "atan2f",
    "sinh", "sinhf", "cosh", "coshf", "tanh", "tanhf",
    "asinh", "asinhf", "acosh", "acoshf", "atanh", "atanhf",
    "sqrt", "sqrtf", "cbrt", "cbrtf",
    "pow", "powf",
    "fabs", "fabsf",
    "floor", "floorf", "ceil", "ceilf", "round", "roundf", "trunc", "truncf",
    "fmod", "fmodf"
}

def _memmove_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Handles taint propagation through `memmove` (and similar functions like `memcpy`).
    If the source buffer is tainted, this rule taints the destination buffer and stops
    further recursion into `memmove` itself.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    if current_pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
        return False

    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)
    if not called_function_obj or called_function_obj.getName() not in ["memmove", "memcpy"]:
        return False

    # Standard signature is (dest, src, size).
    # P-code inputs are [call_target, dest, src, size]
    if current_pcode_op.getNumInputs() < 3: # Need at least dest and src
        return False

    dest_vn = current_pcode_op.getInput(1)
    src_vn = current_pcode_op.getInput(2)

    src_hv = src_vn.getHigh() if src_vn else None
    dest_hv = dest_vn.getHigh() if dest_vn else None

    # Check if the source is tainted
    if src_hv and src_hv in tainted_hvs:
        analyzer.println("INFO: [RULE_{}] Detected call with tainted source: {}".format(
            called_function_obj.getName().upper(),
            analyzer._get_varnode_representation(src_hv, high_func)
        ))

        # Taint the destination if it's not already tainted
        if dest_hv and dest_hv not in tainted_hvs:
            tainted_hvs.add(dest_hv)
            dest_hv_repr = analyzer._get_varnode_representation(dest_hv, high_func)
            tainted_hvs_repr.add(dest_hv_repr)
            
            analyzer.println("INFO: [RULE_{}] Propagating taint to destination: {}".format(
                called_function_obj.getName().upper(),
                dest_hv_repr
            ))
            
            # Log this special propagation
            analyzer.all_tainted_usages.append({
                "originating_imported_function_name": origin_log_name,
                "function_name": high_func.getFunction().getName(),
                "function_entry": high_func.getFunction().getEntryPoint().toString(),
                "address": current_pcode_op.getSeqnum().getTarget().toString(),
                "pcode_op_str": str(current_pcode_op),
                "usage_type": "TAINT_PROPAGATED_BY_RULE",
                "tainted_component_repr": dest_hv_repr,
                "details": "Taint propagated from source ({}) to destination ({}) by {} rule.".format(
                    analyzer._get_varnode_representation(src_hv, high_func),
                    dest_hv_repr,
                    called_function_obj.getName()
                )
            })

        # This rule has handled the call, so don't do the default recursion.
        return True

    return False

def _math_lib_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Handles taint propagation through common math library functions.
    If any input argument is tainted, this rule taints the return value and
    stops further recursion into the math function itself.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    if current_pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
        return False

    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)
    if not called_function_obj or called_function_obj.getName() not in _MATH_LIB_FUNCTIONS:
        return False

    # Check if any input argument is tainted.
    is_any_arg_tainted = False
    tainted_arg_reprs = []
    # P-code inputs for a call are [call_target, arg1, arg2, ...]
    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()):
        arg_vn = current_pcode_op.getInput(pcode_arg_idx)
        arg_hv = arg_vn.getHigh() if arg_vn else None
        if arg_hv and arg_hv in tainted_hvs:
            is_any_arg_tainted = True
            tainted_arg_reprs.append(analyzer._get_varnode_representation(arg_hv, high_func))

    if is_any_arg_tainted:
        analyzer.println("INFO: [RULE_MATH] Detected call to '{}' with tainted argument(s): {}".format(
            called_function_obj.getName(),
            ", ".join(tainted_arg_reprs)
        ))

        # Taint the return value (output) of the call
        output_vn = current_pcode_op.getOutput()
        if output_vn:
            output_hv = output_vn.getHigh()
            if output_hv and output_hv not in tainted_hvs:
                tainted_hvs.add(output_hv)
                output_hv_repr = analyzer._get_varnode_representation(output_hv, high_func)
                tainted_hvs_repr.add(output_hv_repr)
                
                analyzer.println("INFO: [RULE_MATH] Propagating taint to return value: {}".format(
                    output_hv_repr
                ))

                # Log this special propagation
                analyzer.all_tainted_usages.append({
                    "originating_imported_function_name": origin_log_name,
                    "function_name": high_func.getFunction().getName(),
                    "function_entry": high_func.getFunction().getEntryPoint().toString(),
                    "address": current_pcode_op.getSeqnum().getTarget().toString(),
                    "pcode_op_str": str(current_pcode_op),
                    "usage_type": "TAINT_PROPAGATED_BY_RULE",
                    "tainted_component_repr": output_hv_repr,
                    "details": "Taint propagated through math function '{}' from arg(s) ({}) to return value.".format(
                        called_function_obj.getName(),
                        ", ".join(tainted_arg_reprs)
                    )
                })
        
        # This rule has handled the call, so don't do the default recursion.
        return True

    return False

def _deallocation_rule_handler(analyzer, op_idx, all_pcode_ops, high_func, tainted_hvs, tainted_hvs_repr, origin_log_name):
    """
    Handles taint termination for deallocation functions like `operator delete` or `free`.
    If a tainted pointer is passed to be deallocated, this is a sink, and the path is terminated.
    """
    current_pcode_op = all_pcode_ops[op_idx]
    if current_pcode_op.getMnemonic() not in ["CALL", "CALLIND"]:
        return False

    called_function_obj = analyzer._get_called_function_from_pcode_op(current_pcode_op)
    if not called_function_obj:
        return False

    func_name = called_function_obj.getName()
    # Keywords to identify deallocation functions. Catches "operator delete", "free", etc.
    dealloc_keywords = ["delete", "free"] 
    is_dealloc_call = any(keyword in func_name.lower() for keyword in dealloc_keywords)

    if not is_dealloc_call:
        return False

    # Standard signature is (ptr). P-code inputs are [call_target, ptr]
    if current_pcode_op.getNumInputs() < 2:
        return False

    ptr_vn = current_pcode_op.getInput(1)
    ptr_hv = ptr_vn.getHigh() if ptr_vn else None

    # Check if the pointer being deallocated is tainted
    if ptr_hv and ptr_hv in tainted_hvs:
        ptr_repr = analyzer._get_varnode_representation(ptr_hv, high_func)
        analyzer.println("INFO: [RULE_DEALLOC] Tainted pointer {} is being deallocated by call to '{}'. Terminating path.".format(
            ptr_repr,
            func_name
        ))

        # Log this as a terminal sink
        analyzer.all_tainted_usages.append({
            "originating_imported_function_name": origin_log_name,
            "function_name": high_func.getFunction().getName(),
            "function_entry": high_func.getFunction().getEntryPoint().toString(),
            "address": current_pcode_op.getSeqnum().getTarget().toString(),
            "pcode_op_str": str(current_pcode_op),
            "usage_type": "TAINTED_POINTER_DEALLOCATED",
            "tainted_component_repr": ptr_repr,
            "details": "Tainted pointer passed to deallocation function '{}', terminating taint propagation.".format(func_name)
        })

        # This rule has handled the call, so don't do the default recursion.
        return True

    return False

class TaintAnalyzer:
    """
    Encapsulates the entire taint analysis process.
    """
    # -------------------
    # Class Configuration
    # -------------------
    MAX_RECURSION_DEPTH = 5
    UNRESOLVED_CALL_EXPLORE_BUDGET = 3

    def __init__(self, current_program, monitor, println, printerr, askFile, rule_handlers=None, aggressive_branch_filtering=False, report_all_usage_types=False):
        """
        Initializes the analyzer with necessary Ghidra services and state.
        :param rule_handlers: A list of functions to handle special taint propagation rules.
        :param aggressive_branch_filtering: If True, filters out tainted branches that are only dependent on CPU flags.
        :param report_all_usage_types: If True, all usage types will be printed and saved, ignoring the default filter.
        """
        # Ghidra services
        self.current_program = current_program
        self.monitor = monitor
        self.println = println
        self.printerr = printerr
        self.askFile = askFile
        self.func_manager = current_program.getFunctionManager()
        self.ref_manager = current_program.getReferenceManager()
        self.decompiler = DecompInterface()
        options = DecompileOptions()
        self.decompiler.setOptions(options)
        self.decompiler.openProgram(self.current_program)

        # Define which usage types are reported by default.
        # This allows selective reporting for different analysis stages.
        self.default_usage_types_to_report = {
            "TAINTED_ARG_TO_CALL_RECURSION",
            "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
            "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP",
            "TAINTED_ARG_TO_UNRESOLVED_CALL",
            "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
            "RETURN_TAINTED_VALUE",
            "TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN",
            "TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG",
            "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN",
            "TAINTED_MEMORY_ACCESS",
            "TAINTED_POINTER_DEALLOCATED",
            "TAINT_PROPAGATED_TO_CALLER_VIA_PARAM"
        }
        self.decompiler_timeout_secs = 60

        # Define which usage types are reported by default.
        # This allows selective reporting for different analysis stages.
        self.all_usage_types = self.default_usage_types_to_report.union({
            "BRANCH_CONDITION_TAINTED",
            "TAINTED_COMPARISON"
        })

        # Analysis state
        self.all_tainted_usages = []
        self.visited_function_states = set()
        self.rule_handlers = [_memmove_rule_handler, _math_lib_rule_handler, _deallocation_rule_handler] # Add the built-in memmove and math handlers
        if rule_handlers:
            self.rule_handlers.extend(rule_handlers) # Add any user-provided handlers
        self.aggressive_branch_filtering = aggressive_branch_filtering
        self.pending_analysis_tasks = []
        self.report_all_usage_types = report_all_usage_types
        
    def __del__(self):
        """
        Dispose of the decompiler when the object is destroyed.
        """
        if self.decompiler:
            self.decompiler.dispose()
            self.println("DEBUG: Decompiler disposed.")

    # -------------------
    # Helper/Utility Methods (formerly global functions)
    # -------------------
    def cleanup_operand_repr(self, repr_str):
        """
        Cleans up the string representation of a varnode or operand for cleaner output.
        - Extracts register names like "w19" from "iVar1_4(w19)".
        - Extracts constants like "0x60" from "UnnamedHighVar(Constant: 0x60".
        - Removes surrounding parentheses or other artifacts.
        """
        if not hasattr(self, 're'):
            import re
            self.re = re

        s = str(repr_str)

        # 1. Look for register names like w19, x21, s2, d7 (e.g., from "puVar13(x21)")
        match = self.re.search(r'\(([wxsd]\d+)\)', s)
        if match:
            return match.group(1)
            
        # 2. Look for hexadecimal constants (e.g., from "UnnamedHighVar(Constant: 0x60")
        match = self.re.search(r'Constant: (0x[0-9a-fA-F]+)', s)
        if match:
            return match.group(1)

        # 3. Fallback for simple cases like "0x60)" or "#0x10"
        s = s.strip()
        
        if s.startswith('#'):
            s = s[1:]
        
        return s

    def _get_stack_offset_from_varnode_recursive(self, varnode, high_func, recursion_depth=0, max_depth=5):
        """
        Recursively trace a varnode back to its origin to find if it's derived
        from a stack variable.
        """
        self.println("  - [STACK_SEARCH.{}] Analyzing varnode: {}".format(recursion_depth, varnode))

        if not varnode or recursion_depth >= max_depth:
            self.println("  - [STACK_SEARCH.{}] Max depth or null varnode. Aborting.".format(recursion_depth))
            return None

        # Case 1: The varnode itself is a direct stack address.
        addr = varnode.getAddress()
        self.println("  - [STACK_SEARCH.{}] Details: isAddress={}, addr={}, isStackAddress={}".format(
            recursion_depth,
            varnode.isAddress(),
            addr,
            addr.isStackAddress() if addr else "N/A"
        ))
        if addr is not None and addr.isStackAddress():
            offset = addr.getOffset()
            self.println("  - [STACK_SEARCH.{}] SUCCESS (Direct): Varnode is a direct stack address with offset {:#x}.".format(recursion_depth, offset))
            return offset

        def_op = varnode.getDef()
        if not def_op:
            self.println("  - [STACK_SEARCH.{}] No defining p-code op found. Aborting path.".format(recursion_depth))
            return None

        mnemonic = def_op.getMnemonic()
        self.println("  - [STACK_SEARCH.{}] Def P-Code Op: {}".format(recursion_depth, def_op))
        
        # Case 2: Base case - An operation relative to the stack pointer (SP) or frame pointer (FP).
        if mnemonic in ["PTRADD", "PTRSUB"]:
            sp_reg = self.current_program.getCompilerSpec().getStackPointer()
            fp_reg = None
            lang_id_str = self.current_program.getLanguageID().getIdAsString().lower()
            if 'aarch64' in lang_id_str:
                fp_reg = self.current_program.getRegister("x29")
            elif 'x86' in lang_id_str:
                fp_reg = self.current_program.getRegister("rbp") if '64' in lang_id_str else self.current_program.getRegister("ebp")

            stack_base_regs = [r.getAddress() for r in [sp_reg, fp_reg] if r is not None]

            # Handle 3-input PTRADD for array-like access: base + index * scale
            if mnemonic == "PTRADD" and def_op.getNumInputs() == 3:
                base_vn = def_op.getInput(0)
                index_vn = def_op.getInput(1)
                scale_vn = def_op.getInput(2)
                if index_vn.isConstant() and scale_vn.isConstant():
                    base_offset = self._get_stack_offset_from_varnode_recursive(base_vn, high_func, recursion_depth + 1, max_depth)
                    if base_offset is not None:
                        const_offset = index_vn.getOffset() * scale_vn.getOffset()
                        final_offset = base_offset + const_offset
                        self.println("  - [STACK_SEARCH.{}] SUCCESS (PTRADD3): Found stack base {:#x} with offset {:#x} -> final offset {:#x}.".format(recursion_depth, base_offset, const_offset, final_offset))
                        return final_offset

            # Handle 2-input PTRADD/PTRSUB
            base_ptr_vn = def_op.getInput(0)
            offset_vn = def_op.getInput(1)

            # Heuristic 2.1: Check for OP(base, const) where base is SP or FP.
            if base_ptr_vn.isRegister() and base_ptr_vn.getAddress() in stack_base_regs and offset_vn.isConstant():
                offset = offset_vn.getOffset()
                self.println("  - [STACK_SEARCH.{}] SUCCESS (Base Ptr): Found {} with stack base and offset {:#x}.".format(recursion_depth, mnemonic, offset))
                return offset

            # Heuristic 2.2: Check for PTRADD(const, base) where base is SP or FP.
            if mnemonic == "PTRADD" and offset_vn.isRegister() and offset_vn.getAddress() in stack_base_regs and base_ptr_vn.isConstant():
                offset = base_ptr_vn.getOffset()
                self.println("  - [STACK_SEARCH.{}] SUCCESS (Base Ptr): Found {} with stack base and offset {:#x}.".format(recursion_depth, mnemonic, offset))
                return base_ptr_vn.getOffset()

            # Heuristic 2.3 (Enhanced): Recursively check if the base of the PTRADD/PTRSUB is itself a stack address.
            if offset_vn.isConstant():
                base_offset = self._get_stack_offset_from_varnode_recursive(base_ptr_vn, high_func, recursion_depth + 1, max_depth)
                if base_offset is not None:
                    # We need to handle signed offsets correctly from the constant varnode.
                    const_val = offset_vn.getOffset()
                    if const_val > 0x7FFFFFFFFFFFFFFF: # Simple check for large unsigned as negative
                       const_val = const_val - 0x10000000000000000
                    
                    final_offset = 0
                    if mnemonic == "PTRADD":
                        final_offset = base_offset + const_val
                    else: # PTRSUB
                        final_offset = base_offset - const_val
                    
                    self.println("  - [STACK_SEARCH.{}] SUCCESS (Recursive Base): Found {} with recursive stack base {:#x} and offset {:#x} -> final offset {:#x}.".format(recursion_depth, mnemonic, base_offset, const_val, final_offset))
                    return final_offset

        # Case 3: Recursive step for ops that pass through a value (e.g., COPY, CAST).
        # NEW: Also treat INDIRECT as a passthrough for taint purposes.
        if mnemonic in ["COPY", "CAST", "INDIRECT"]:
            self.println("  - [STACK_SEARCH.{}] Recursing through {}...".format(recursion_depth, mnemonic))
            return self._get_stack_offset_from_varnode_recursive(def_op.getInput(0), high_func, recursion_depth + 1, max_depth)
        
        # Case 4: Recursive step for control-flow joins (MULTIEQUAL).
        if mnemonic == "MULTIEQUAL":
            self.println("  - [STACK_SEARCH.{}] Recursing through MULTIEQUAL...".format(recursion_depth))
            # Check all branches of the MULTIEQUAL. If any path leads to a stack offset, use it.
            for i in range(def_op.getNumInputs()):
                result = self._get_stack_offset_from_varnode_recursive(def_op.getInput(i), high_func, recursion_depth + 1, max_depth)
                if result is not None:
                    self.println("  - [STACK_SEARCH.{}] SUCCESS (MultiEqual): Found stack offset {:#x} in one of the branches.".format(recursion_depth, result))
                    return result

        self.println("  - [STACK_SEARCH.{}] Mnemonic '{}' is not a handled case. Aborting path.".format(recursion_depth, mnemonic))
        return None

    def _is_varnode_tainted_recursive(self, varnode, high_func, tainted_hvs, visited_ops=None):
        """
        Recursively checks if a varnode is tainted, traversing through COPY and MULTIEQUAL ops.
        """
        if visited_ops is None:
            visited_ops = set()

        # Base case 1: Direct high variable is tainted
        hv = varnode.getHigh()
        if hv and hv in tainted_hvs:
            return True
            
        # Base case 2: Representative varnode's high variable is tainted (handles aliasing)
        if hv:
            rep_vn = hv.getRepresentative()
            if rep_vn:
                rep_hv = rep_vn.getHigh()
                if rep_hv and rep_hv in tainted_hvs:
                    return True

        def_op = varnode.getDef()
        if not def_op or def_op.getSeqnum() in visited_ops:
            return False

        visited_ops.add(def_op.getSeqnum())
        mnemonic = def_op.getMnemonic()

        # Recursive step for ops that pass through a value
        if mnemonic in ["COPY", "CAST"]:
            return self._is_varnode_tainted_recursive(def_op.getInput(0), high_func, tainted_hvs, visited_ops)
        
        # Recursive step for control-flow joins
        if mnemonic == "MULTIEQUAL":
            for i in range(def_op.getNumInputs()):
                if self._is_varnode_tainted_recursive(def_op.getInput(i), high_func, tainted_hvs, visited_ops):
                    return True
        
        # NEW: Recursive step for LOAD operations
        if mnemonic == "LOAD":
            # The value is loaded from the address specified in the second input
            addr_vn = def_op.getInput(1)
            # Check if the address itself is tainted
            if self._is_varnode_tainted_recursive(addr_vn, high_func, tainted_hvs, visited_ops):
                return True

        return False

    def _get_varnode_representation(self, varnode_obj, high_function_context):
        if varnode_obj is None: return "None"
        if high_function_context:
            actual_high_var_target = varnode_obj
            if not isinstance(varnode_obj, HighVariable):
                actual_high_var_target = varnode_obj.getHigh()
            if actual_high_var_target:
                display_name = actual_high_var_target.getName()
                storage_info_str = None
                symbol = actual_high_var_target.getSymbol()
                if symbol:
                    if symbol.getName() and symbol.getName() != "UnnamedSymbol":
                        if not display_name or ("Unnamed" in display_name and "Unnamed" not in symbol.getName()):
                            display_name = symbol.getName()
                    elif not display_name:
                        display_name = symbol.getName()
                    try:
                        vs = symbol.getStorage()
                        if vs and not vs.isInvalidStorage():
                            storage_info_str = vs.toString()
                    except AttributeError: pass
                if storage_info_str is None:
                    rep_vn = actual_high_var_target.getRepresentative()
                    if rep_vn:
                        if rep_vn.isRegister():
                            reg = self.current_program.getLanguage().getRegister(rep_vn.getAddress(), rep_vn.getSize())
                            storage_info_str = reg.getName() if reg else "Register"
                        elif rep_vn.getAddress() is not None and rep_vn.getAddress().isStackAddress():
                            storage_info_str = "Stack[{:#x}]".format(actual_high_var_target.getStackOffset()) if hasattr(actual_high_var_target, 'getStackOffset') else "StackDirect[{}]".format(rep_vn.getAddress().toString(True))
                        elif rep_vn.isUnique():
                            storage_info_str = "UniquePcode[0x{:x}]".format(rep_vn.getOffset())
                        elif rep_vn.isConstant():
                            storage_info_str = "Constant: 0x{:x}".format(rep_vn.getOffset())
                        elif rep_vn.getAddress() is not None and rep_vn.getAddress().isMemoryAddress() and not rep_vn.getAddress().isStackAddress():
                             storage_info_str = "GlobalMem[{}]".format(rep_vn.getAddress().toString(True))
                    if storage_info_str is None and isinstance(actual_high_var_target, ghidra.program.model.pcode.HighOther):
                         storage_info_str = "HighOther"
                if display_name is None : display_name = "UnnamedHighVar"
                if storage_info_str:
                    return "{}({})".format(display_name, storage_info_str)
                else:
                    return "{} (HighVar Repr)".format(display_name)
        if varnode_obj.isRegister():
            reg = self.current_program.getLanguage().getRegister(varnode_obj.getAddress(), varnode_obj.getSize())
            return reg.getName() if reg else "reg_vn:{}".format(varnode_obj.getAddress())
        if varnode_obj.isConstant():
            return "Constant: 0x{:x}".format(varnode_obj.getOffset())
        if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isStackAddress():
            return "stack_vn_direct:{}".format(varnode_obj.getAddress().toString(True))
        if varnode_obj.isUnique():
            def_op = varnode_obj.getDef()
            if def_op:
                return "unique_vn:{}(def:{}) (size {})".format(varnode_obj.getOffset(), def_op.getMnemonic(), varnode_obj.getSize())
            return "unique_vn:{} (size {})".format(varnode_obj.getOffset(), varnode_obj.getSize())
        if varnode_obj.getAddress() is not None and varnode_obj.getAddress().isMemoryAddress():
            return "mem_vn:{}".format(varnode_obj.getAddress().toString(True))
        return varnode_obj.toString()

    def _log_unresolved_call_with_tainted_args(self, pcode_op, current_high_func, tainted_hvs_from_caller,
                                             current_func_name, current_func_entry_addr_obj, op_addr_obj,
                                             originating_imported_func_name_for_log, context_msg=""):
        target_addr_vn = pcode_op.getInput(0)
        for arg_idx in range(1, pcode_op.getNumInputs()):
            arg_vn = pcode_op.getInput(arg_idx)
            arg_hv = arg_vn.getHigh() if arg_vn else None
            if arg_hv and arg_hv in tainted_hvs_from_caller:
                details_str = "Tainted argument #{} ({}) passed to unresolved call (target: {}). {}".format(
                    arg_idx - 1,
                    self._get_varnode_representation(arg_vn, current_high_func),
                    self._get_varnode_representation(target_addr_vn, current_high_func),
                    context_msg
                )
                self.all_tainted_usages.append({
                    "originating_imported_function_name": originating_imported_func_name_for_log,
                    "function_name": current_func_name,
                    "function_entry": current_func_entry_addr_obj.toString(),
                    "address": op_addr_obj.toString(),
                    "pcode_op_str": str(pcode_op),
                    "usage_type": "TAINTED_ARG_TO_UNRESOLVED_CALL",
                    "tainted_component_repr": self._get_varnode_representation(arg_vn, current_high_func),
                    "details": details_str.strip()
                })
                self.println("WARN: [{} @ {}] {}. Cannot recurse or explore further.".format(current_func_name, op_addr_obj.toString(), details_str.strip()))
                break

    def _get_called_function_from_pcode_op(self, pcode_op):
        """
        Helper to resolve the called function from a CALL or CALLIND PcodeOp.
        """
        called_function_obj = None
        op_address = pcode_op.getSeqnum().getTarget()
        target_func_addr_vn = pcode_op.getInput(0)
        
        if pcode_op.getMnemonic() == "CALL" and target_func_addr_vn.isConstant():
            try:
                called_func_address = self.current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                if called_func_address:
                    called_function_obj = self.func_manager.getFunctionAt(called_func_address)
            except Exception:
                pass
        
        # Fallback or for CALLIND
        if called_function_obj is None:
            # For CALLIND, the target is in a register, so we check references from the instruction
            ref_iter = self.ref_manager.getReferencesFrom(op_address, 0)
            for ref in ref_iter:
                if ref.getReferenceType().isCall():
                    func_from_ref = self.func_manager.getFunctionAt(ref.getToAddress())
                    if func_from_ref:
                        called_function_obj = func_from_ref
                        break
        return called_function_obj

    # -------------------
    # Core Taint Tracing Logic (as a method)
    # -------------------
    def _trace_taint_in_function(self, high_func_to_analyze, initial_tainted_hvs, pcode_op_start_taint, originating_imported_func_name_for_log, current_depth=0,
                                sub_recursion_budget=None, current_sub_depth=0, analysis_config=None, initial_tainted_stack_offsets=None, tainted_memory_regions=None):
        if current_depth > self.MAX_RECURSION_DEPTH:
            self.println("DEBUG: Max recursion depth ({}) reached.".format(self.MAX_RECURSION_DEPTH))
            return

        if sub_recursion_budget is not None and current_sub_depth >= sub_recursion_budget:
            self.println("DEBUG: Sub-recursion budget ({}) reached. Stopping this sub-path for {}.".format(
                sub_recursion_budget, high_func_to_analyze.getFunction().getName()
            ))
            return

        func_entry_addr = high_func_to_analyze.getFunction().getEntryPoint()
        func_name = high_func_to_analyze.getFunction().getName()

        initial_tainted_hvs_repr_list = sorted([self._get_varnode_representation(hv, high_func_to_analyze) for hv in initial_tainted_hvs])
        initial_tainted_hvs_repr_tuple = tuple(initial_tainted_hvs_repr_list)
        current_state_key = (func_entry_addr.toString(), initial_tainted_hvs_repr_tuple, originating_imported_func_name_for_log)

        if current_state_key in self.visited_function_states:
            self.println("DEBUG: Already analyzed function {} with initial taints {} (origin: {}). Skipping.".format(func_name, initial_tainted_hvs_repr_tuple, originating_imported_func_name_for_log))
            return
        self.visited_function_states.add(current_state_key)

        self.println("\\n>>> Analyzing function: {} (Depth: {}) at {} (Originating from: {}) with initial taints: {}".format(
            func_name, current_depth, func_entry_addr, originating_imported_func_name_for_log,
            ", ".join([self._get_varnode_representation(hv, high_func_to_analyze) for hv in initial_tainted_hvs])
        ))

        current_func_input_param_hvs = set()
        try:
            local_symbol_map = high_func_to_analyze.getLocalSymbolMap()
            if local_symbol_map:
                symbol_iterator = local_symbol_map.getSymbols()
                while symbol_iterator.hasNext():
                    sym = symbol_iterator.next()
                    if sym and sym.isParameter():
                        hv = sym.getHighVariable()
                        if hv: current_func_input_param_hvs.add(hv)
        except Exception as e:
            self.printerr("Error getting input parameters for {}: {}".format(func_name, e))

        tainted_high_vars_in_current_func = set(initial_tainted_hvs)
        tainted_high_var_representations_in_current_func = set()
        tainted_stack_offsets = set(initial_tainted_stack_offsets) if initial_tainted_stack_offsets else set()
        if tainted_memory_regions is None:
            tainted_memory_regions = set()

        # NEW: Proactively find and taint stack offsets from the initial set of tainted HighVariables.
        # This is crucial for catching cases where a tainted pointer (not just the stack pointer)
        # is used to access the stack.
        for hv in list(tainted_high_vars_in_current_func): # Use a copy to modify the set during iteration
            # Representative varnode is the best chance to get a concrete definition
            vn = hv.getRepresentative()
            if vn:
                stack_offset = self._get_stack_offset_from_varnode_recursive(vn, high_func_to_analyze)
                if stack_offset is not None:
                    if stack_offset not in tainted_stack_offsets:
                        tainted_stack_offsets.add(stack_offset)
                        self.println("DEBUG: [STACK_RULE] Proactively tainted stack offset {:#x} from initial HighVar: {}".format(
                            stack_offset, self._get_varnode_representation(hv, high_func_to_analyze)
                        ))

        if tainted_stack_offsets:
            self.println("DEBUG: [STACK_TAINTS] Initial tainted stack offsets for this function: {}".format(
                [hex(offset) for offset in tainted_stack_offsets]
            ))

        for hv_init in initial_tainted_hvs:
            tainted_high_var_representations_in_current_func.add(
                self._get_varnode_representation(hv_init, high_func_to_analyze)
            )

        # Convert iterator to list to allow indexed access for forward scanning
        all_pcode_ops_in_func = []
        op_iter_for_analysis = high_func_to_analyze.getPcodeOps()
        while op_iter_for_analysis.hasNext():
            all_pcode_ops_in_func.append(op_iter_for_analysis.next())

        start_idx = 0
        if pcode_op_start_taint:
            # If a start op is specified, find its index
            for i, op in enumerate(all_pcode_ops_in_func):
                if op.getSeqnum().equals(pcode_op_start_taint.getSeqnum()):
                    start_idx = i
                    self.println("\\nDEBUG: Reached specified start PcodeOp {} at {} in {}, subsequent ops will be processed.".format(
                        op, op.getSeqnum().getTarget().toString(), func_name
                    ))
                    break
        else:
             self.println("DEBUG: Starting taint analysis from the beginning of function {}.".format(func_name))


        for op_idx in range(start_idx, len(all_pcode_ops_in_func)):
            current_pcode_op = all_pcode_ops_in_func[op_idx]
            current_op_address = current_pcode_op.getSeqnum().getTarget()
            current_op_address_str = current_op_address.toString()
            
            # --- DEBUG ---
            try:
                current_addr_val = int(current_op_address_str, 16)
                if 0x18c7e4 <= current_addr_val <= 0x18c7fc:
                    self.println("DEBUG IR @ {}: {}".format(current_op_address_str, current_pcode_op))
            except ValueError:
                pass # Ignore if address string is not a valid hex number
            # --- END DEBUG ---
            
            output_vn = current_pcode_op.getOutput()
            output_hv = output_vn.getHigh() if output_vn else None
            mnemonic = current_pcode_op.getMnemonic()

            # Taint propagation through CBRANCH
            if mnemonic == "CBRANCH":
                condition_vn = current_pcode_op.getInput(1)
                is_condition_tainted = self._is_varnode_tainted_recursive(
                    condition_vn,
                    high_func_to_analyze,
                    tainted_high_vars_in_current_func
                )
                
                # --- Find Comparison Operands ---
                # Default to an empty list.
                final_compared_ops = []
                def_op_cond = condition_vn.getDef()
                
                # Try to find the defining comparison operation for the branch condition.
                if def_op_cond and def_op_cond.getMnemonic() in ["INT_EQUAL", "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS", "INT_LESSEQUAL", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL"]:
                #if def_op_cond and def_op_cond.getMnemonic() in ["FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL"]:
                    self.println("DEBUG: [CBRANCH] Found defining op for condition: {}".format(def_op_cond))
                    op1_vn = def_op_cond.getInput(0)
                    op2_vn = def_op_cond.getInput(1)
                    op1_repr = self._get_varnode_representation(op1_vn, high_func_to_analyze)
                    op2_repr = self._get_varnode_representation(op2_vn, high_func_to_analyze)
                    final_compared_ops = [op1_repr, op2_repr]
                
                # --- Create and Log the Usage Report ---
                instruction_at_op = self.current_program.getListing().getInstructionAt(current_op_address)
                
                # --- Exclusion Rules for Branches ---
                should_exclude_branch = False

                # Rule 0: Filter out stack canary checks.
                is_stack_canary_check = any("__stack_chk_guard" in op_repr for op_repr in final_compared_ops)
                if is_stack_canary_check:
                    should_exclude_branch = True
                    self.println("INFO: [FILTER] Skipping branch at {} because it appears to be a stack canary check.".format(current_op_address_str))

                if not should_exclude_branch and instruction_at_op:
                    mnemonic_lower = instruction_at_op.getMnemonicString().lower()
                    # Rule 1: Skip common, low-level branch instructions like 'cbz' and 'cbnz'.
                    if mnemonic_lower in ["cbz", "cbnz"]:
                        should_exclude_branch = True
                        self.println("INFO: [FILTER] Skipping branch at {} from instruction '{}'.".format(current_op_address_str, mnemonic_lower))
                    
                    # Rule 2: (REMOVED) This rule was too aggressive and hid important results.
                    # The original rule was:
                    # if not should_exclude_branch:
                    #     prev_instruction = instruction_at_op.getPrevious()
                    #     if prev_instruction and prev_instruction.getMnemonicString().lower() == 'cmp':
                    #         should_exclude_branch = True
                    #         self.println("INFO: [FILTER] Skipping branch at {} because it is preceded by a 'cmp' instruction.".format(current_op_address_str))

                # --- Log the Usage Report if Not Excluded ---
                if not should_exclude_branch:
                    self.all_tainted_usages.append({
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name,
                        "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str,
                        "pcode_op_str": str(current_pcode_op),
                        "usage_type": "BRANCH_CONDITION_TAINTED",
                        "tainted_component_repr": self._get_varnode_representation(condition_vn, high_func_to_analyze),
                        "compared_ops_repr": final_compared_ops, # Use the list directly
                        "instruction_mnemonic": instruction_at_op.getMnemonicString() if instruction_at_op else "N/A",
                        "details": "Tainted condition for branch."
                    })
                    # Also log to console for immediate feedback
                    self.println("INFO: [{} @ {}] Taint reached CBRANCH. Operands: {}. ".format(
                        func_name, current_op_address_str, final_compared_ops
                    ))

            # --- Sink Checks End ---

            # Taint propagation through standard operations
            if mnemonic == "STORE":
                stored_value_vn = current_pcode_op.getInput(2)
                stored_value_hv = stored_value_vn.getHigh() if stored_value_vn else None
                if stored_value_hv and stored_value_hv in tainted_high_vars_in_current_func:
                    dest_addr_vn = current_pcode_op.getInput(1)
                    dest_addr_hv = dest_addr_vn.getHigh() if dest_addr_vn else None

                    # --- [BEGIN] NEW MEMORY REGION TAINTING LOGIC with ALIASING HEURISTIC ---
                    if dest_addr_hv:
                        if dest_addr_hv not in tainted_memory_regions:
                            tainted_memory_regions.add(dest_addr_hv)
                            self.println("DEBUG: [MEMORY_RULE] Tainting memory region pointed to by: {}".format(
                                self._get_varnode_representation(dest_addr_hv, high_func_to_analyze)
                            ))
                        
                        self._apply_aliasing_heuristic(dest_addr_hv, high_func_to_analyze, tainted_memory_regions)
                    # --- [END] NEW MEMORY REGION TAINTING LOGIC with ALIASING HEURISTIC ---
                    
                    usage_entry_store = {
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                        "tainted_component_repr": self._get_varnode_representation(stored_value_vn, high_func_to_analyze),
                        "destination_repr": self._get_varnode_representation(dest_addr_vn, high_func_to_analyze)
                    }
                    if dest_addr_hv and dest_addr_hv in current_func_input_param_hvs and dest_addr_hv not in initial_tainted_hvs:
                        self.println("NEW LOGIC: Instead of terminating, propagate taint back to callers.")
                        self._propagate_taint_to_callers_via_param(
                            dest_addr_hv, high_func_to_analyze, current_pcode_op,
                            originating_imported_func_name_for_log, analysis_config
                        )
                        return # This path is now handled by the multi-stage analysis, so we can return.
                    else:
                        usage_entry_store["usage_type"] = "STORE_TAINTED_VALUE"
                        usage_entry_store["details"] = "Tainted value stored."
                        self.all_tainted_usages.append(usage_entry_store)

            elif mnemonic == "RETURN":
                if current_pcode_op.getNumInputs() > 1:
                    returned_value_vn = current_pcode_op.getInput(1)
                    
                    # Determine if the return value is tainted using the new robust check.
                    is_return_tainted = self._is_varnode_tainted_recursive(
                        returned_value_vn,
                        high_func_to_analyze,
                        tainted_high_vars_in_current_func
                    )

                    self.println("DEBUG: [{} @ {}] Analyzing potential tainted RETURN with value: {} (Tainted: {})".format(
                        func_name,
                        current_op_address_str,
                        self._get_varnode_representation(returned_value_vn, high_func_to_analyze),
                        is_return_tainted
                    ))
                    
                    # --- Enhanced Debugging Information ---
                    if not is_return_tainted: # Only print detailed debug info if the check fails
                        self.println("    [DEBUG] --- Taint Check Details (RETURN FAILED) ---")
                        def_op_for_debug = returned_value_vn.getDef()
                        def_op_str = "None"
                        if def_op_for_debug:
                            def_op_str = "{} at {}".format(str(def_op_for_debug), def_op_for_debug.getSeqnum().getTarget().toString())
                        self.println("    [DEBUG]   > Return Varnode: {} (Size: {}, Def: {})".format(
                            returned_value_vn.toString(),
                            returned_value_vn.getSize(),
                            def_op_str
                        ))
                        
                        self.println("    [DEBUG]   > Currently Tainted HighVariables in this function:")
                        if not tainted_high_vars_in_current_func:
                            self.println("    [DEBUG]     - (empty set)")
                        else:
                            # Sort for consistent output
                            sorted_tainted_hvs = sorted(
                                list(tainted_high_vars_in_current_func), 
                                key=lambda x: self._get_varnode_representation(x, high_func_to_analyze)
                            )
                            for idx, hv in enumerate(sorted_tainted_hvs):
                                self.println("    [DEBUG]     {}. {}".format(idx + 1, self._get_varnode_representation(hv, high_func_to_analyze)))
                        self.println("    [DEBUG] ---------------------------------")
                    
                    if is_return_tainted:
                        instruction_at_op = self.current_program.getListing().getInstructionAt(current_op_address)
                        tainted_comp_repr = self._get_varnode_representation(returned_value_vn, high_func_to_analyze)
                        self.all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "RETURN_TAINTED_VALUE", 
                            "tainted_component_repr": tainted_comp_repr,
                            "instruction_mnemonic": instruction_at_op.getMnemonicString() if instruction_at_op else "N/A"
                        })
                        
                        # Generate detailed log output for this event
                        self.println("\n" + "="*20 + " TAINTED RETURN DETECTED " + "="*20)
                        self.println("  - Taint Origin:    {}".format(originating_imported_func_name_for_log))
                        self.println("  - Function:        {} (Depth: {})".format(high_func_to_analyze.getFunction().getPrototypeString(True, True), current_depth))
                        self.println("  - Return Address:  {}".format(current_op_address_str))
                        self.println("  - Instruction:     {}".format(instruction_at_op.toString()))
                        self.println("  - Tainted Value:   {}".format(tainted_comp_repr))
                        
                        def_op = returned_value_vn.getDef()
                        if def_op:
                            self.println("  - Value defined by:  {} at {}".format(str(def_op), def_op.getSeqnum().getTarget().toString()))
                        
                        self.println("="*64 + "\n")

                        # --- [BEGIN] Multi-Stage Analysis Task Creation ---
                        # Find all call sites of the current function and queue them for the next stage of analysis.
                        current_function_obj = high_func_to_analyze.getFunction()
                        self.println("INFO: [MULTI-STAGE] Tainted return from '{}'. Finding call sites to continue analysis.".format(current_function_obj.getName()))
                        
                        call_site_refs = self.ref_manager.getReferencesTo(current_function_obj.getEntryPoint())
                        
                        for ref in call_site_refs:
                            if not ref.getReferenceType().isCall():
                                continue
                                
                            caller_func = self.func_manager.getFunctionContaining(ref.getFromAddress())
                            if not caller_func:
                                continue
                                
                            # Decompile the caller to find the exact call operation
                            try:
                                decompile_res_caller = self.decompiler.decompileFunction(caller_func, self.decompiler_timeout_secs, self.monitor)
                                if decompile_res_caller and decompile_res_caller.getHighFunction():
                                    high_caller_func = decompile_res_caller.getHighFunction()
                                    
                                    # Find the call op at the reference address
                                    call_op_in_caller = None
                                    op_iter_caller = high_caller_func.getPcodeOps(ref.getFromAddress())
                                    while op_iter_caller.hasNext():
                                        pcode_op = op_iter_caller.next()
                                        if pcode_op.getMnemonic() in ["CALL", "CALLIND"]:
                                            call_op_in_caller = pcode_op
                                            break
                                    
                                    if call_op_in_caller and call_op_in_caller.getOutput():
                                        output_hv = call_op_in_caller.getOutput().getHigh()
                                        if output_hv:
                                            new_task = {
                                                "high_func_to_analyze": high_caller_func,
                                                "initial_tainted_hvs": {output_hv},
                                                "pcode_op_start_taint": call_op_in_caller,
                                                "originating_imported_func_name_for_log": "tainted_return_from_{}".format(current_function_obj.getName()),
                                                "analysis_config": analysis_config,
                                                "tainted_memory_regions": set() # Start fresh for the new analysis path
                                            }
                                            self.pending_analysis_tasks.append(new_task)
                                            self.println("INFO: [MULTI-STAGE] Queued new task to analyze caller '{}' starting from tainted return.".format(caller_func.getName()))

                            except Exception as e:
                                self.printerr("ERROR: [MULTI-STAGE] Failed to process call site at {} in {}: {}".format(ref.getFromAddress(), caller_func.getName(), e))
                        # --- [END] Multi-Stage Analysis Task Creation ---

            
            if mnemonic in ["CALL", "CALLIND"]:
                # --- [BEGIN] Tainted Memory Access Sink Detection ---
                # Check if a tainted value is used as the target address for an indirect call
                target_addr_vn = current_pcode_op.getInput(0)
                target_addr_hv = target_addr_vn.getHigh() if target_addr_vn else None
                if target_addr_hv and target_addr_hv in tainted_high_vars_in_current_func:
                    self.all_tainted_usages.append({
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                        "usage_type": "TAINTED_INDIRECT_CALL_TARGET",
                        "tainted_component_repr": self._get_varnode_representation(target_addr_hv, high_func_to_analyze),
                        "details": "Tainted value used as the target for an indirect call."
                    })
                # --- [END] Tainted Memory Access Sink Detection ---

                called_function_obj = self._get_called_function_from_pcode_op(current_pcode_op)
                
                if called_function_obj:
                    # --- Custom Rule Handling ---
                    was_handled_by_rule = False
                    for handler in self.rule_handlers:
                        # A handler should return True if it processed the op and no further generic processing is needed.
                        if handler(self, op_idx, all_pcode_ops_in_func, high_func_to_analyze, tainted_high_vars_in_current_func, tainted_high_var_representations_in_current_func, originating_imported_func_name_for_log):
                            was_handled_by_rule = True
                            break
                    
                    if was_handled_by_rule:
                        continue
                    # --- END Custom Rule Handling ---

                    # First, check if any arguments are tainted.
                    is_any_arg_tainted = False
                    tainted_args_for_log = []
                    tainted_arg_hvs = []
                    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()):
                        caller_arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                        caller_arg_hv = caller_arg_vn.getHigh()
                        if caller_arg_hv and caller_arg_hv in tainted_high_vars_in_current_func:
                            is_any_arg_tainted = True
                            tainted_args_for_log.append(self._get_varnode_representation(caller_arg_hv, high_func_to_analyze))
                            tainted_arg_hvs.append(caller_arg_hv)

                    # --- [BEGIN] NEW TAINT OUT-DEGREE ANALYSIS ---
                    # If a tainted value is passed to a function, assume it might taint any pointer arguments passed to the same function.
                    if is_any_arg_tainted:
                        for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()):
                            arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                            arg_hv = arg_vn.getHigh() if arg_vn else None
                            
                            # Check if this argument is a pointer and is NOT one of the already tainted arguments.
                            if arg_hv and isinstance(arg_hv.getDataType(), Pointer) and arg_hv not in tainted_arg_hvs:
                                # Heuristic: Does this pointer point to a local stack variable? (e.g. passing &my_vector)
                                arg_def_op = arg_vn.getDef()
                                if arg_def_op:
                                    # This pattern often indicates taking the address of a local variable.
                                    # e.g., (unique, 0x11f80, 8) PTRSUB (register, 0x8, 8) , (const, 0xffffffffffffffe0, 8)
                                    if arg_def_op.getMnemonic() in ["PTRSUB", "PTRADD"] and arg_def_op.getInput(0).isRegister():
                                        
                                        # It's a pointer to a local, taint its memory region and potential aliases.
                                        if arg_hv not in tainted_memory_regions:
                                            tainted_memory_regions.add(arg_hv)
                                            self.println("DEBUG: [OUT-DEGREE] Tainting memory region of {} due to call with other tainted args.".format(
                                                self._get_varnode_representation(arg_hv, high_func_to_analyze)
                                            ))
                                            
                                            # Also trigger the aliasing heuristic for this newly tainted region pointer.
                                            self._apply_aliasing_heuristic(arg_hv, high_func_to_analyze, tainted_memory_regions)

                    # --- [END] NEW TAINT OUT-DEGREE ANALYSIS ---

                    # If the call is to a thunk function and has tainted arguments, apply special taint propagation rules.
                    if called_function_obj.isExternal() and is_any_arg_tainted:
                        self.println("INFO: [THUNK_CALL] Tainted arg(s) {} passed to thunk function '{}'. Not recursing, applying special taint propagation.".format(
                            ", ".join(tainted_args_for_log),
                            called_function_obj.getName()
                        ))
                        
                        # Rule 1: Taint the return value of the thunk call.
                        call_output_vn = current_pcode_op.getOutput()
                        if call_output_vn:
                            call_output_hv = call_output_vn.getHigh()
                            if call_output_hv and call_output_hv not in tainted_high_vars_in_current_func:
                                tainted_high_vars_in_current_func.add(call_output_hv)
                                output_hv_repr = self._get_varnode_representation(call_output_hv, high_func_to_analyze)
                                tainted_high_var_representations_in_current_func.add(output_hv_repr)
                                self.println("DEBUG: [THUNK_CALL] Tainting return value: {}".format(output_hv_repr))
                                self.all_tainted_usages.append({
                                    "originating_imported_function_name": originating_imported_func_name_for_log,
                                    "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                    "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                                    "usage_type": "TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN",
                                    "tainted_component_repr": output_hv_repr,
                                    "details": "Return value of thunk call {} tainted due to tainted input(s).".format(called_function_obj.getName())
                                })
                        
                        # Rule 2: Taint any input parameters that are pointers.
                        for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()):
                            arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                            arg_hv = arg_vn.getHigh()
                            if arg_hv and isinstance(arg_hv.getDataType(), Pointer):
                                if arg_hv not in tainted_high_vars_in_current_func:
                                    tainted_high_vars_in_current_func.add(arg_hv)
                                    arg_hv_repr = self._get_varnode_representation(arg_hv, high_func_to_analyze)
                                    tainted_high_var_representations_in_current_func.add(arg_hv_repr)
                                    self.println("DEBUG: [THUNK_CALL] Tainting pointer argument: {}".format(arg_hv_repr))
                                    self.all_tainted_usages.append({
                                        "originating_imported_function_name": originating_imported_func_name_for_log,
                                        "function_name": func_name, "function_entry": func_entry_addr.toString(),
                                        "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                                        "usage_type": "TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG",
                                        "tainted_component_repr": arg_hv_repr,
                                        "details": "Input pointer argument to thunk call {} is now tainted.".format(called_function_obj.getName())
                                    })
                        
                        continue # Skip the normal recursion logic and move to the next p-code op.
                
                high_called_func = None
                if called_function_obj: # Ensure we have a function object before trying to decompile
                    #self.println("USER DEBUG: Attempting to decompile function: {}".format(called_function_obj.getName()))
                    try:
                        decompile_res_callee = self.decompiler.decompileFunction(called_function_obj, 60, self.monitor)
                        #self.println("USER DEBUG: Decompilation result object: {}".format(decompile_res_callee))
                        if decompile_res_callee and decompile_res_callee.getHighFunction(): high_called_func = decompile_res_callee.getHighFunction()
                    except Exception as de: self.printerr("ERROR: Decompile callee {}: {}".format(called_function_obj.getName(), de))
                
                if high_called_func:
                    #self.println("USER DEBUG: Entering 'if high_called_func' block for recursion.")
                    callee_func_proto = high_called_func.getFunctionPrototype()
                    num_formal_params = callee_func_proto.getNumParams() if callee_func_proto else -1 # Use -1 to indicate no proto
                    #self.println("USER DEBUG: [PARAM_MAP] Callee: {}, Prototype: {}, Num formal params: {}".format(high_called_func.getFunction().getName(), callee_func_proto, num_formal_params))
                    newly_tainted_callee_hvs = set()
                    tainted_arg_details_for_no_map = []
                    for pcode_arg_idx in range(1, current_pcode_op.getNumInputs()): 
                        caller_arg_vn = current_pcode_op.getInput(pcode_arg_idx)
                        caller_arg_hv = caller_arg_vn.getHigh()
                        if caller_arg_hv and caller_arg_hv in tainted_high_vars_in_current_func:
                            conceptual_arg_idx = pcode_arg_idx - 1
                            #self.println("USER DEBUG: [PARAM_MAP] Found tainted caller arg#{} -> conceptual_arg_idx #{}".format(pcode_arg_idx, conceptual_arg_idx))
                            tainted_arg_details_for_no_map.append("PCodeArg#{}:{}".format(conceptual_arg_idx, self._get_varnode_representation(caller_arg_vn, high_func_to_analyze)))
                            if callee_func_proto and conceptual_arg_idx < num_formal_params:
                                #self.println("USER DEBUG: [PARAM_MAP] Arg index is within formal param count. Attempting to get param symbol.")
                                callee_param_symbol = callee_func_proto.getParam(conceptual_arg_idx)
                                #self.println("USER DEBUG: [PARAM_MAP] Callee param symbol object: {}".format(callee_param_symbol))
                                hv_to_taint = callee_param_symbol.getHighVariable() if callee_param_symbol else None
                                #self.println("USER DEBUG: [PARAM_MAP] HighVariable to be tainted in callee: {}".format(hv_to_taint))
                                if hv_to_taint: 
                                    newly_tainted_callee_hvs.add(hv_to_taint)
                                    #self.println("USER DEBUG: [PARAM_MAP] Successfully added HighVariable to the new taint set.")
                                else: 
                                    self.println("WARN: Tainted arg for {}, but no HighVar for callee param #{}. This could be due to optimized out param or incorrect signature.".format(called_function_obj.getName(),conceptual_arg_idx ))
                            else: 
                                #self.println("USER DEBUG: [PARAM_MAP] Arg index {} is OUTSIDE formal param count {}. Cannot map.".format(conceptual_arg_idx, num_formal_params))
                                pass
                    
                    #self.println("USER DEBUG: [PARAM_MAP] Finished param mapping. Size of newly_tainted_callee_hvs: {}".format(len(newly_tainted_callee_hvs)))
                    if newly_tainted_callee_hvs:
                        #self.println("USER DEBUG: [PARAM_MAP] Entering 'if newly_tainted_callee_hvs' block to start recursion.")
                        self.all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_RECURSION",
                            "details": "Recursive call to {} ({}) with taints: {}.".format(called_function_obj.getName(), mnemonic, ", ".join([self._get_varnode_representation(h, high_called_func) for h in newly_tainted_callee_hvs]))
                        })
                        self._trace_taint_in_function(high_called_func, newly_tainted_callee_hvs, None, originating_imported_func_name_for_log, current_depth + 1, sub_recursion_budget=sub_recursion_budget, current_sub_depth=current_sub_depth +1 if sub_recursion_budget is not None else 0, analysis_config=analysis_config, tainted_memory_regions=tainted_memory_regions)
                    elif tainted_arg_details_for_no_map: # Tainted args exist but couldn't be mapped
                        #self.println("USER DEBUG: [PARAM_MAP] Entering 'elif tainted_arg_details_for_no_map' block. Recursion might happen with empty taint set.")
                        self.all_tainted_usages.append({
                            "originating_imported_function_name": originating_imported_func_name_for_log,
                            "function_name": func_name, "function_entry": func_entry_addr.toString(),
                            "address": current_op_address_str, "pcode_op_str": str(current_pcode_op),
                            "usage_type": "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
                            "details": "Tainted PCode args ({}) to {} ({}) cannot map to HighProto (count {}).".format(", ".join(tainted_arg_details_for_no_map), called_function_obj.getName(), mnemonic, num_formal_params)
                        })
                        self._trace_taint_in_function(high_called_func, newly_tainted_callee_hvs, None, originating_imported_func_name_for_log, current_depth + 1, sub_recursion_budget=sub_recursion_budget, current_sub_depth=current_sub_depth +1 if sub_recursion_budget is not None else 0, analysis_config=analysis_config, tainted_memory_regions=tainted_memory_regions)
                else: # Unresolved call
                    #self.println("USER DEBUG: Entering 'else' block for unresolved call.")
                    target_func_addr_vn = current_pcode_op.getInput(0)
                    potential_target_addr_to_explore = None; exploration_context_msg = ""
                    if target_func_addr_vn.isConstant():
                        try:
                            addr = self.current_program.getAddressFactory().getAddress(hex(target_func_addr_vn.getOffset()))
                            if addr: potential_target_addr_to_explore = addr; exploration_context_msg = "PCode target const addr {}".format(addr)
                        except: pass
                    elif target_func_addr_vn.isAddress() and target_func_addr_vn.getAddress().isMemoryAddress() and not target_func_addr_vn.getAddress().isStackAddress():
                        pointer_loc_addr = target_func_addr_vn.getAddress()
                        try:
                            mem = self.current_program.getMemory()
                            ptr_val = mem.getLong(pointer_loc_addr) if self.current_program.getDefaultPointerSize() == 8 else (mem.getInt(pointer_loc_addr) & 0xFFFFFFFF)
                            addr = self.current_program.getAddressFactory().getAddress(hex(ptr_val))
                            if addr: potential_target_addr_to_explore = addr; exploration_context_msg = "PCode target RAM {}, read ptr {} -> target {}".format(pointer_loc_addr, hex(ptr_val), addr)
                        except: pass
                    if potential_target_addr_to_explore and (current_depth < self.MAX_RECURSION_DEPTH):
                        attempted_func_obj = self.func_manager.getFunctionAt(potential_target_addr_to_explore)
                        if attempted_func_obj:
                            high_attempted_func = None
                            try:
                                decompile_res_attempt = self.decompiler.decompileFunction(attempted_func_obj, 60, self.monitor)
                                if decompile_res_attempt and decompile_res_attempt.getHighFunction(): high_attempted_func = decompile_res_attempt.getHighFunction()
                            except: pass
                            if high_attempted_func:
                                attempted_callee_proto = high_attempted_func.getFunctionPrototype()
                                num_formal_attempted = attempted_callee_proto.getNumParams() if attempted_callee_proto else 0
                                newly_tainted_attempt = set(); any_tainted_arg_for_attempt = False; tainted_arg_details_attempt_no_map = []
                                for arg_idx_pcode_attempt in range(1, current_pcode_op.getNumInputs()):
                                    arg_vn_attempt = current_pcode_op.getInput(arg_idx_pcode_attempt)
                                    arg_hv_attempt = arg_vn_attempt.getHigh()
                                    if arg_hv_attempt and arg_hv_attempt in tainted_high_vars_in_current_func:
                                        any_tainted_arg_for_attempt = True
                                        tainted_arg_details_attempt_no_map.append("PCodeArg#{}:{}".format(arg_idx_pcode_attempt-1, self._get_varnode_representation(arg_vn_attempt, high_func_to_analyze)))
                                        if attempted_callee_proto and (arg_idx_pcode_attempt -1) < num_formal_attempted:
                                            param_sym_att = attempted_callee_proto.getParam(arg_idx_pcode_attempt -1)
                                            hv_to_taint_att = param_sym_att.getHighVariable() if param_sym_att else None
                                            if hv_to_taint_att: newly_tainted_attempt.add(hv_to_taint_att)
                                if newly_tainted_attempt:
                                    self.all_tainted_usages.append({"originating_imported_function_name": originating_imported_func_name_for_log, "function_name": func_name, "function_entry": func_entry_addr.toString(), "address": current_op_address_str, "pcode_op_str": str(current_pcode_op), "usage_type": "EXPLORING_INITIALLY_UNRESOLVED_CALL", "details": "Exploring {} to {} ({}) with taints. Budget: {}.".format(mnemonic, attempted_func_obj.getName(), exploration_context_msg, self.UNRESOLVED_CALL_EXPLORE_BUDGET)})
                                    self._trace_taint_in_function(high_attempted_func, newly_tainted_attempt, None, originating_imported_func_name_for_log, current_depth + 1, sub_recursion_budget=self.UNRESOLVED_CALL_EXPLORE_BUDGET, current_sub_depth=0, analysis_config=analysis_config, tainted_memory_regions=tainted_memory_regions)
                                elif any_tainted_arg_for_attempt:
                                     self.all_tainted_usages.append({"originating_imported_function_name": originating_imported_func_name_for_log, "function_name": func_name, "function_entry": func_entry_addr.toString(), "address": current_op_address_str, "pcode_op_str": str(current_pcode_op), "usage_type": "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP", "details": "Tainted args ({}) to {} (resolved to {}), but no HighProto map. {}".format(", ".join(tainted_arg_details_attempt_no_map), mnemonic, attempted_func_obj.getName(), exploration_context_msg)})
                            else: self._log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, originating_imported_func_name_for_log, "(decomp failed for explored {})".format(exploration_context_msg))
                        else: self._log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, originating_imported_func_name_for_log, "(no func obj at explored {})".format(exploration_context_msg))
                    else: self._log_unresolved_call_with_tainted_args(current_pcode_op, high_func_to_analyze, tainted_high_vars_in_current_func, func_name, func_entry_addr, current_op_address, originating_imported_func_name_for_log, "(cannot explore target)")

            if output_hv and output_hv not in tainted_high_vars_in_current_func:
                is_newly_tainted = False
                source_of_taint_repr = "N/A"

                # --- [BEGIN] Refactored Taint Propagation Logic ---

                # Rule 1: Handle LOAD operations separately and with detailed logging.
                if mnemonic == "LOAD":
                    load_addr_vn = current_pcode_op.getInput(1)
                    self.println("DEBUG: [LOAD_HANDLER] Checking LOAD op at {}. Address varnode: {}".format(current_op_address_str, load_addr_vn))

                    # Heuristic 1.1: Check if loading from a tainted stack offset.
                    if tainted_stack_offsets:
                        # Use the new, more powerful recursive search for the load address
                        load_stack_offset = self._get_stack_offset_from_varnode_recursive(load_addr_vn, high_func_to_analyze)
                        
                        # Rule 1.1.1: Direct match on the final calculated offset
                        if load_stack_offset is not None and load_stack_offset in tainted_stack_offsets:
                            is_newly_tainted = True
                            source_of_taint_repr = "Tainted Stack Location [offset {:#x}]".format(load_stack_offset)
                            self.println("DEBUG: [LOAD_HANDLER] STACK_RULE SUCCESS (direct): Tainting output due to load from tainted stack offset {:#x}.".format(load_stack_offset))

                        # Rule 1.1.2: Check if loading from an address based on a tainted stack variable (struct/array access)
                        if not is_newly_tainted:
                            load_addr_def_op = load_addr_vn.getDef()
                            if load_addr_def_op and load_addr_def_op.getMnemonic() == "PTRADD":
                                base_vn = load_addr_def_op.getInput(0)
                                base_offset = self._get_stack_offset_from_varnode_recursive(base_vn, high_func_to_analyze)
                                if base_offset is not None and base_offset in tainted_stack_offsets:
                                    is_newly_tainted = True
                                    offset_vn = load_addr_def_op.getInput(1)
                                    field_offset = offset_vn.getOffset() if offset_vn.isConstant() else '?'
                                    source_of_taint_repr = "Tainted Stack Location [base {:#x} + field {}]".format(base_offset, "{:#x}".format(field_offset) if isinstance(field_offset, (int, long)) else field_offset)
                                    self.println("DEBUG: [LOAD_HANDLER] STACK_RULE SUCCESS (base): Tainting output due to load from tainted stack base {:#x}.".format(base_offset))

                    # Heuristic 1.2: Check if the address pointer itself is tainted.
                    if not is_newly_tainted:
                        # Use the more robust recursive check to see if the address itself is tainted.
                        if self._is_varnode_tainted_recursive(load_addr_vn, high_func_to_analyze, tainted_high_vars_in_current_func):
                            is_newly_tainted = True
                            load_addr_repr = self._get_varnode_representation(load_addr_vn, high_func_to_analyze)
                            source_of_taint_repr = "Tainted Address Pointer ({})".format(load_addr_repr)
                            self.println("DEBUG: [LOAD_HANDLER] POINTER_RULE SUCCESS: Tainting output due to load from tainted address pointer (recursive check).")
                            
                            # NEW: Also taint the address pointer itself to propagate the taint through pointer arithmetic.
                            load_addr_hv = load_addr_vn.getHigh()
                            if load_addr_hv and load_addr_hv not in tainted_high_vars_in_current_func:
                                tainted_high_vars_in_current_func.add(load_addr_hv)
                                tainted_high_var_representations_in_current_func.add(load_addr_repr)
                                self.println("DEBUG: [LOAD_HANDLER] POINTER_RULE PROPAGATION: Tainting the address pointer '{}' itself.".format(load_addr_repr))

                        else:
                            self.println("DEBUG: [LOAD_HANDLER] POINTER_RULE FAIL: Address varnode {} is not tainted (recursive check).".format(self._get_varnode_representation(load_addr_vn, high_func_to_analyze)))
                    
                    # Heuristic 1.3: Check if loading from a tainted memory region (new rule).
                    if not is_newly_tainted:
                        load_addr_hv = load_addr_vn.getHigh()
                        # --- [BEGIN] ENHANCED REGION RULE with BASE+OFFSET support ---
                        is_tainted_by_region = False
                        if load_addr_hv and load_addr_hv in tainted_memory_regions:
                            is_tainted_by_region = True
                            source_of_taint_repr = "Tainted Memory Region via pointer ({})".format(
                                self._get_varnode_representation(load_addr_hv, high_func_to_analyze)
                            )
                        else:
                            # Check for PTRADD base
                            def_op = load_addr_vn.getDef()
                            if def_op and def_op.getMnemonic() == "PTRADD":
                                base_vn = def_op.getInput(0)
                                base_hv = base_vn.getHigh()
                                if base_hv:
                                    # --- FINAL FIX: Compare by representative varnode ---
                                    base_rep = base_hv.getRepresentative()
                                    for tainted_region_hv in tainted_memory_regions:
                                        tainted_rep = tainted_region_hv.getRepresentative()
                                        if base_rep and tainted_rep and base_rep.equals(tainted_rep):
                                            is_tainted_by_region = True
                                            source_of_taint_repr = "Tainted Memory Region via base pointer ({})".format(
                                                self._get_varnode_representation(base_hv, high_func_to_analyze)
                                            )
                                            break # Found a match
                                    # --- END FINAL FIX ---

                        if is_tainted_by_region:
                            is_newly_tainted = True
                            self.println("DEBUG: [LOAD_HANDLER] REGION_RULE SUCCESS: Tainting output due to load from a tainted memory region.")
                        else:
                            self.println("DEBUG: [LOAD_HANDLER] REGION_RULE FAIL: Address pointer {} is not in the tainted memory regions set.".format(
                                self._get_varnode_representation(load_addr_hv, high_func_to_analyze)
                            ))
                        # --- [END] ENHANCED REGION RULE with BASE+OFFSET support ---
                
                # Rule 2: Handle all other operations that propagate taint.
                else:
                    inputs_to_check = []
                    unary_ops = ["COPY", "CAST", "INT_NEGATE", "INT_2COMP", "POPCOUNT", "INT_ZEXT", "INT_SEXT", "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT2FLOAT", "TRUNC", "CEIL", "FLOOR", "ROUND", "INT2FLOAT", "FLOAT2INT", "BOOL_NEGATE"]
                    multi_ops = ["INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR", "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL", "INT_SLESSEQUAL", "FLOAT_ADD", "FLOAT_SUB", "FLOAT_MULT", "FLOAT_DIV", "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL", "BOOL_XOR", "BOOL_AND", "BOOL_OR", "MULTIEQUAL", "PIECE", "SUBPIECE", "PTRADD", "PTRSUB"]

                    if mnemonic in unary_ops and current_pcode_op.getNumInputs() > 0:
                        inputs_to_check.append(current_pcode_op.getInput(0))
                    elif mnemonic in multi_ops:
                        # For SUBPIECE, only the first operand (the larger piece) matters for taint source.
                        if mnemonic == "SUBPIECE" and current_pcode_op.getNumInputs() > 0:
                            inputs_to_check.append(current_pcode_op.getInput(0))
                        else:
                            for i in range(current_pcode_op.getNumInputs()):
                                inputs_to_check.append(current_pcode_op.getInput(i))

                    for input_vn in inputs_to_check:
                        if input_vn:
                            input_hv = input_vn.getHigh()
                            if input_hv and input_hv in tainted_high_vars_in_current_func:
                                is_newly_tainted = True
                                source_of_taint_repr = self._get_varnode_representation(input_hv, high_func_to_analyze)
                                # Found a tainted input, no need to check others for this op
                                break
                
                # --- [END] Refactored Taint Propagation Logic ---

                if is_newly_tainted:
                    should_add_taint_prop = True; is_strlen_call_output = False
                    if mnemonic in ["CALL", "CALLIND"] and output_vn and output_vn.getHigh() == output_hv:
                        called_func_strlen_check = None; target_vn_strlen = current_pcode_op.getInput(0)
                        if mnemonic == "CALL" and target_vn_strlen.isConstant():
                            try:
                                addr_strlen = self.current_program.getAddressFactory().getAddress(hex(target_vn_strlen.getOffset()))
                                if addr_strlen: called_func_strlen_check = self.func_manager.getFunctionAt(addr_strlen)
                            except: pass
                        else:
                            ref_iter_strlen = self.ref_manager.getReferencesFrom(current_op_address, 0)
                            for ref_strlen in ref_iter_strlen:
                                if ref_strlen.getReferenceType().isCall():
                                    func_from_ref_strlen = self.func_manager.getFunctionAt(ref_strlen.getToAddress())
                                    if func_from_ref_strlen: called_func_strlen_check = func_from_ref_strlen; break
                        if called_func_strlen_check and called_func_strlen_check.getName() == "strlen": is_strlen_call_output = True
                    if is_strlen_call_output:
                        self.println("DEBUG: [STRLEN SUPPRESSION] Output of strlen CALL {} will NOT be tainted.".format(self._get_varnode_representation(output_hv, high_func_to_analyze)))
                        should_add_taint_prop = False
                    if should_add_taint_prop:
                        tainted_high_vars_in_current_func.add(output_hv)
                        output_hv_repr_set = self._get_varnode_representation(output_hv, high_func_to_analyze)
                        tainted_high_var_representations_in_current_func.add(output_hv_repr_set)
                        self.println("DEBUG: [{} @ {}] Taint propagated from {} to {} via {}.".format(func_name, current_op_address_str, source_of_taint_repr, output_hv_repr_set, mnemonic))
                        #self.println("USER DEBUG: P-code for propagation is: {}".format(current_pcode_op))

            if output_hv and output_hv in tainted_high_vars_in_current_func:
                if output_hv in current_func_input_param_hvs and output_hv not in initial_tainted_hvs:
                    # NEW LOGIC: Instead of terminating, propagate taint back to callers.
                    self._propagate_taint_to_callers_via_param(
                        output_hv, high_func_to_analyze, current_pcode_op,
                        originating_imported_func_name_for_log, analysis_config
                    )
                    return # This path is now handled by the multi-stage analysis, so we can return.

            # --- [BEGIN] Tainted Comparison Sink Check ---
            comparison_mnemonics = {
                "INT_EQUAL", "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_LESS", "INT_LESSEQUAL",
                "FLOAT_EQUAL", "FLOAT_NOTEQUAL", "FLOAT_LESS", "FLOAT_LESSEQUAL"
            }
            if mnemonic in comparison_mnemonics:
                is_any_input_tainted = False
                tainted_input_repr = "N/A"
                for i in range(current_pcode_op.getNumInputs()):
                    input_vn = current_pcode_op.getInput(i)
                    if self._is_varnode_tainted_recursive(input_vn, high_func_to_analyze, tainted_high_vars_in_current_func):
                        is_any_input_tainted = True
                        tainted_input_repr = self._get_varnode_representation(input_vn, high_func_to_analyze)
                        break # Found one, no need to check others

                if is_any_input_tainted:
                    op1_vn = current_pcode_op.getInput(0)
                    op2_vn = current_pcode_op.getInput(1)
                    op1_repr = self._get_varnode_representation(op1_vn, high_func_to_analyze)
                    op2_repr = self._get_varnode_representation(op2_vn, high_func_to_analyze)
                    final_compared_ops = [op1_repr, op2_repr]
                    
                    instruction_at_op = self.current_program.getListing().getInstructionAt(current_op_address)

                    self.all_tainted_usages.append({
                        "originating_imported_function_name": originating_imported_func_name_for_log,
                        "function_name": func_name,
                        "function_entry": func_entry_addr.toString(),
                        "address": current_op_address_str,
                        "pcode_op_str": str(current_pcode_op),
                        "usage_type": "TAINTED_COMPARISON",
                        "tainted_component_repr": tainted_input_repr,
                        "compared_ops_repr": final_compared_ops,
                        "instruction_mnemonic": instruction_at_op.getMnemonicString() if instruction_at_op else "N/A",
                        "details": "Tainted value used in a comparison operation ({}).".format(mnemonic)
                    })
                    self.println("INFO: [{} @ {}] Taint reached COMPARISON op ({}). Operands: {}.".format(
                        func_name, current_op_address_str, mnemonic, final_compared_ops
                    ))
            # --- [END] Tainted Comparison Sink Check ---

        self.println("<<< Finished analyzing function: {}.".format(func_name))

    def _apply_aliasing_heuristic(self, dest_addr_hv, high_func_to_analyze, tainted_memory_regions):
        """
        Heuristic: If a tainted pointer is a stack variable, taint nearby stack
        variables that are also pointers, assuming they are part of the same struct
        (e.g., std::vector).
        """
        try:
            symbol_p = dest_addr_hv.getSymbol()
            if symbol_p and symbol_p.getStorage().isStackStorage():
                offset_p = symbol_p.getStorage().getStackOffset()
                self.println("DEBUG: [ALIASING] Tainted store pointer {} is a stack var at offset {:#x}".format(dest_addr_hv.getName(), offset_p))

                local_symbols = high_func_to_analyze.getLocalSymbolMap().getSymbols()
                while local_symbols.hasNext():
                    symbol_q = local_symbols.next()
                    # Ensure we have a valid symbol with stack storage and a HighVariable
                    if not symbol_q or not symbol_q.getStorage().isStackStorage():
                        continue
                    
                    hv_q = symbol_q.getHighVariable()
                    if not hv_q or hv_q == dest_addr_hv:
                        continue

                    # Check if it's a pointer type and close on the stack
                    if isinstance(hv_q.getDataType(), Pointer):
                        offset_q = symbol_q.getStorage().getStackOffset()
                        if abs(offset_p - offset_q) <= 24: # Heuristic for 3 pointers of 8 bytes
                            if hv_q not in tainted_memory_regions:
                                tainted_memory_regions.add(hv_q)
                                self.println("DEBUG: [ALIASING] Found potential alias {}. Tainting its memory region too.".format(
                                    self._get_varnode_representation(hv_q, high_func_to_analyze)
                                ))
        except Exception as e:
            self.printerr("WARN: [ALIASING] Error during alias analysis heuristic: {}".format(e))
            
    def _propagate_taint_to_callers_via_param(self, tainted_param_hv, high_func, pcode_op, originating_imported_func_name_for_log, analysis_config):
        """
        Handles the case where taint is propagated to a function's input parameter.
        This function will find all call sites of the current function and create new
        analysis tasks to propagate the taint back to the arguments in the caller functions.
        """
        func_name = high_func.getFunction().getName()
        
        # 1. Find the index of the tainted parameter.
        proto = high_func.getFunctionPrototype()
        num_params = proto.getNumParams()
        tainted_param_index = -1
        for i in range(num_params):
            param = proto.getParam(i)
            # Ensure we are comparing the same HighVariable instance
            if param and param.getHighVariable() and param.getHighVariable().getRepresentative().equals(tainted_param_hv.getRepresentative()):
                tainted_param_index = i
                break
        
        if tainted_param_index == -1:
            self.printerr("WARN: [PARAM_PROPAGATION] Could not find index for tainted parameter {} in {}. Cannot propagate to callers.".format(
                self._get_varnode_representation(tainted_param_hv, high_func), func_name
            ))
            return

        # 2. Log this special propagation event.
        details_str = "Taint propagated to parameter #{} ({}) of '{}'. Taint will now be propagated back to all call sites.".format(
            tainted_param_index,
            self._get_varnode_representation(tainted_param_hv, high_func),
            func_name
        )
        self.all_tainted_usages.append({
            "originating_imported_function_name": originating_imported_func_name_for_log,
            "function_name": func_name,
            "function_entry": high_func.getFunction().getEntryPoint().toString(),
            "address": pcode_op.getSeqnum().getTarget().toString(),
            "pcode_op_str": str(pcode_op),
            "usage_type": "TAINT_PROPAGATED_TO_CALLER_VIA_PARAM",
            "tainted_component_repr": self._get_varnode_representation(tainted_param_hv, high_func),
            "details": details_str
        })
        self.println("INFO: [PARAM_PROPAGATION] " + details_str)

        # 3. Find all call sites and queue new analysis tasks for the callers.
        current_function_obj = high_func.getFunction()
        call_site_refs = self.ref_manager.getReferencesTo(current_function_obj.getEntryPoint())
        
        for ref in call_site_refs:
            if not ref.getReferenceType().isCall():
                continue
                
            caller_func = self.func_manager.getFunctionContaining(ref.getFromAddress())
            if not caller_func:
                continue
                
            try:
                decompile_res_caller = self.decompiler.decompileFunction(caller_func, self.decompiler_timeout_secs, self.monitor)
                if decompile_res_caller and decompile_res_caller.getHighFunction():
                    high_caller_func = decompile_res_caller.getHighFunction()
                    
                    # Find the exact call p-code operation in the caller function.
                    call_op_in_caller = None
                    op_iter_caller = high_caller_func.getPcodeOps(ref.getFromAddress())
                    while op_iter_caller.hasNext():
                        pcode_op_caller = op_iter_caller.next()
                        if pcode_op_caller.getMnemonic() in ["CALL", "CALLIND"]:
                            call_op_in_caller = pcode_op_caller
                            break
                    
                    if call_op_in_caller:
                        # P-code arguments are [target, arg0, arg1, ...], so we need index + 1
                        pcode_arg_index = tainted_param_index + 1
                        if pcode_arg_index < call_op_in_caller.getNumInputs():
                            arg_vn = call_op_in_caller.getInput(pcode_arg_index)
                            arg_hv = arg_vn.getHigh()
                            if arg_hv:
                                new_task = {
                                    "high_func_to_analyze": high_caller_func,
                                    "initial_tainted_hvs": {arg_hv},
                                    "pcode_op_start_taint": call_op_in_caller,
                                    "originating_imported_func_name_for_log": "tainted_param_from_{}".format(current_function_obj.getName()),
                                    "analysis_config": analysis_config,
                                    "tainted_memory_regions": set() # Start with a fresh set of memory regions for the new path
                                }
                                self.pending_analysis_tasks.append(new_task)
                                self.println("INFO: [PARAM_PROPAGATION] Queued new task for caller '{}' from tainted parameter.".format(caller_func.getName()))
                            else:
                                 self.printerr("WARN: [PARAM_PROPAGATION] Tainted parameter corresponds to argument {} which has no HighVariable in caller {}.".format(
                                     self._get_varnode_representation(arg_vn, high_caller_func), caller_func.getName()
                                 ))
                        else:
                            self.printerr("WARN: [PARAM_PROPAGATION] Tainted parameter index {} is out of bounds for call at {} in {}.".format(
                                tainted_param_index, ref.getFromAddress(), caller_func.getName()
                            ))
            except Exception as e:
                self.printerr("ERROR: [PARAM_PROPAGATION] Failed to process call site at {} in {}: {}".format(ref.getFromAddress(), caller_func.getName(), e))

    # -------------------
    # Output/Reporting Methods
    # -------------------
    def _get_filtered_results(self):
        """
        Applies filtering logic to the raw taint usage results based on analyzer settings.
        This centralizes the filtering logic used by both printing and saving functions.
        """
        if not self.all_tainted_usages:
            return []

        # If reporting all types is enabled, no filtering is needed.
        if self.report_all_usage_types:
            return self.all_tainted_usages

        # Default set of usage types to include in reports.
        included_usage_types = {
            "BRANCH_CONDITION_TAINTED",
            "TAINTED_COMPARISON",
            "TAINTED_ARG_TO_CALL_RECURSION",
            "TAINTED_ARG_TO_CALL_NO_PARAM_MAP_OR_VARARGS",
            "TAINTED_ARG_TO_EXPLORED_CALL_NO_PARAM_MAP",
            "TAINTED_ARG_TO_UNRESOLVED_CALL",
            "EXPLORING_INITIALLY_UNRESOLVED_CALL", 
            "RETURN_TAINTED_VALUE",
            "TAINT_PROPAGATED_FROM_THUNK_CALL_RETURN",
            "TAINT_PROPAGATED_TO_THUNK_CALL_POINTER_ARG",
            "TAINT_PROPAGATED_FROM_HOST_CALL_RETURN",
            "TAINTED_MEMORY_ACCESS",
            "TAINT_PROPAGATED_BY_RULE",
            "STORE_TAINTED_VALUE",
            "TAINTED_POINTER_DEALLOCATED",
            "TAINT_PROPAGATED_TO_CALLER_VIA_PARAM"
        }
        
        # Names of CPU flags to filter out if aggressive branch filtering is on.
        cpu_flag_core_names = {
            "tmpcy", "ng", "zf", "cf", "of", "sf", "pf", 
            "tmpnz", "tmpov", "tmpca", "af", 
            "cc_n", "cc_z", "cc_c", "cc_v"
        }

        filtered_results = []
        for res in self.all_tainted_usages:
            usage_type = res.get("usage_type")
            if usage_type not in included_usage_types:
                continue

            # Aggressive branch filtering logic
            if self.aggressive_branch_filtering and usage_type == "BRANCH_CONDITION_TAINTED":
                tainted_comp_repr = res.get("tainted_component_repr", "").lower()
                # A simple heuristic to check if the tainted component is just a CPU flag.
                # e.g., "zf(tmpZR)" or "cf(tmpca)"
                if '(' in tainted_comp_repr and tainted_comp_repr.endswith(')'):
                    content_in_paren = tainted_comp_repr[tainted_comp_repr.rfind('(')+1:-1]
                    if content_in_paren in cpu_flag_core_names:
                        continue # Skip this result
                elif tainted_comp_repr in cpu_flag_core_names:
                    continue # Skip this result

            filtered_results.append(res)
            
        return filtered_results

    def _print_results(self):
        filtered_results_to_print = self._get_filtered_results()
        if not filtered_results_to_print:
            self.println("No tainted usages matching the current filter were found.")
            return

        self.println("\\n--- All Detected Tainted Value Usages (Interprocedural) ---")
        
        usage_counter = 0
        for res in filtered_results_to_print:
            usage_counter += 1
            self.println("Usage #{}:".format(usage_counter))
            if "originating_imported_function_name" in res:
                 self.println("  Originating Lib Call: {}".format(res["originating_imported_function_name"]))
            if "function_name" in res:
                self.println("  Found In Function:   {} at {}".format(res["function_name"], res.get("function_entry", "N/A")))
            self.println("  Instruction Address: {}".format(res["address"]))
            self.println("    PCode Op:            {}".format(res["pcode_op_str"]))
            self.println("    Usage Type:          {}".format(res["usage_type"]))
            if "tainted_component_repr" in res:
                 self.println("    Tainted Component:   {}".format(res["tainted_component_repr"]))
            if "destination_repr" in res:
                 self.println("    Destination Address: {}".format(res["destination_repr"]))
            if "compared_operands" in res:
                 self.println("    Compared Operands:   {} vs {}".format(res["compared_operands"][0], res["compared_operands"][1]))
            if "details" in res and res["details"] is not None:
                 self.println("    Details:             {}".format(res["details"]))
            self.println("-" * 40)

    def _save_results_to_json(self):
        usages_to_process = self._get_filtered_results()
        if not usages_to_process:
            self.println("No tainted usages to save to JSON.")
            return

        output_file_path = None
        # --- Headless Mode Support ---
        # Check for an environment variable to specify the output path, which is ideal for headless execution.
        headless_output_path = os.getenv('TAINT_ANALYSIS_JSON_OUTPUT')
        
        if headless_output_path:
            output_file_path = headless_output_path
            self.println("INFO: TAINT_ANALYSIS_JSON_OUTPUT env var found. Saving results to: {}".format(output_file_path))
        elif self.askFile is None:
            self.printerr("WARN: Headless mode detected (askFile not available) and TAINT_ANALYSIS_JSON_OUTPUT env var not set.")
            output_file_path = "taint_analysis_results.json"
            self.println("WARN: Will attempt to save JSON to default relative path: {}".format(output_file_path))
        else:
            # --- GUI Mode ---
            try:
                output_file_obj = self.askFile("Save Taint Analysis JSON Output", "Save")
                if not output_file_obj:
                    self.println("JSON output cancelled by user.")
                    return
                output_file_path = output_file_obj.getAbsolutePath()
            except Exception as e_askfile:
                self.printerr("Error using askFile function: {}. Falling back to default path.".format(e_askfile))
                output_file_path = "taint_analysis_results.json"
                self.println("Will attempt to save JSON to default path: {}".format(output_file_path))
        
        if not output_file_path:
            self.printerr("Error: Output file path for JSON was not determined. Cannot save results.")
            return

        all_simplified_usages = [] 
        
        for usage in usages_to_process:
            usage_entry_for_json = {
                "originating_imported_function_name": usage.get("originating_imported_function_name", "Unknown_Origin"),
                "found_in_function_name": usage.get("function_name", "N/A"),
                "found_in_function_entry": usage.get("function_entry", "N/A"),
                "instruction_address": usage.get("address", "N/A"),
                "pcode_operation": usage.get("pcode_op_str", "N/A"),
                "usage_type": usage.get("usage_type", "N/A"),
                "tainted_component": usage.get("tainted_component_repr", "N/A")
            }
            if "details" in usage and usage["details"] is not None:
                usage_entry_for_json["details"] = usage["details"]
            if usage.get("usage_type") == "STORE_TAINTED_VALUE" and "destination_repr" in usage:
                usage_entry_for_json["store_destination"] = usage["destination_repr"]
            if usage.get("usage_type") == "BRANCH_CONDITION_TAINTED":
                if "compared_operands" in usage:
                    usage_entry_for_json["branch_compared_operands"] = usage["compared_operands"]
                if "instruction_mnemonic" in usage:
                    usage_entry_for_json["instruction_mnemonic"] = usage["instruction_mnemonic"]
            all_simplified_usages.append(usage_entry_for_json)

        try:
            with open(output_file_path, 'w') as f:
                json.dump(all_simplified_usages, f, indent=4)
            self.println("Taint analysis results saved to: {}".format(output_file_path))
        except IOError as e:
            self.printerr("Failed to write JSON output to file {}: {}".format(output_file_path, e))
        except Exception as e:
            self.printerr("An unexpected error occurred while writing JSON output: {}".format(e))
    
    # -------------------
    # Main Public Method
    # -------------------
    def run(self, target_keywords):
        if not isinstance(target_keywords, list):
            target_keywords = [target_keywords]
        self.println("INFO: Searching for functions, thunks, and call sites related to keywords: {}".format(target_keywords))


        target_ext_funcs = []
        # Using a set to avoid duplicates if multiple keywords match the same function
        found_funcs = set()
        ext_funcs_iter = self.func_manager.getExternalFunctions()
        while ext_funcs_iter.hasNext():
            ext_func = ext_funcs_iter.next()
            for keyword in target_keywords:
                if keyword in ext_func.getName():
                    found_funcs.add(ext_func)

        if not found_funcs:
            self.println("WARN: No external function found with keywords '{}'. Trying all functions...".format(target_keywords))
            all_funcs_iter = self.func_manager.getFunctions(True)
            while all_funcs_iter.hasNext():
                func = all_funcs_iter.next()
                for keyword in target_keywords:
                    if keyword in func.getName():
                        found_funcs.add(func)
        
        target_ext_funcs = list(found_funcs)
        if not target_ext_funcs:
            self.printerr("ERROR: No function found with any of the keywords '{}'. Exiting.".format(target_keywords))
            return

        all_callable_targets = set(target_ext_funcs)
        for ext_func in target_ext_funcs:
            self.println("INFO: Found function '{}'. Searching for its thunks.".format(ext_func.getName()))
            all_funcs_iter = self.func_manager.getFunctions(True)
            while all_funcs_iter.hasNext():
                f = all_funcs_iter.next()
                if f.isThunk():
                    thunked_func = f.getThunkedFunction(True)
                    if thunked_func and thunked_func.equals(ext_func):
                        self.println("INFO: Found thunk '{}' at {} for function.".format(f.getName(), f.getEntryPoint()))
                        all_callable_targets.add(f)

        all_call_sites = set()
        for target in all_callable_targets:
            refs = self.ref_manager.getReferencesTo(target.getEntryPoint())
            for ref in refs:
                if ref.getReferenceType().isCall():
                    all_call_sites.add(ref.getFromAddress())

        if not all_call_sites:
            self.printerr("ERROR: No call sites found for any targets related to keywords '{}'.".format(target_keywords))
            return
            
        self.println("INFO: Found {} unique call sites. Analyzing each...".format(len(all_call_sites)))
        
        # --- Stage 1 Analysis ---
        self.println("\n--- Starting Stage 1 Taint Analysis from '{}' call sites ---".format(target_keywords))
        for call_site_addr in sorted(list(all_call_sites), key=lambda addr: addr.getOffset()):
            self.println("\n--- Analyzing Call Site #{} at {} ---".format(call_site_addr.getOffset(), call_site_addr))
            
            parent_func = self.func_manager.getFunctionContaining(call_site_addr)
            if not parent_func:
                self.printerr("ERROR: No parent function for call site {}. Skipping.".format(call_site_addr))
                continue
            
            self.println("DEBUG: Parent (caller): {} at {}".format(parent_func.getName(), parent_func.getEntryPoint()))
            
            decompile_results = self.decompiler.decompileFunction(parent_func, 60, self.monitor)
            if not decompile_results or not decompile_results.getHighFunction():
                self.printerr("ERROR: Failed to decompile {}. Skipping.".format(parent_func.getName()))
                continue
            
            high_parent_func = decompile_results.getHighFunction()
            
            target_call_op = None
            op_iter = high_parent_func.getPcodeOps(call_site_addr)
            while op_iter.hasNext():
                pcode_op = op_iter.next()
                if pcode_op.getMnemonic() in ["CALL", "CALLIND"]:
                    target_call_op = pcode_op
                    break
            
            if not target_call_op:
                self.printerr("ERROR: No CALL/CALLIND PcodeOp found at call site: {}. Skipping.".format(call_site_addr))
                continue
            
            output_vn = target_call_op.getOutput()
            if not output_vn:
                self.println("INFO: Call at {} has no output varnode. Nothing to taint. Skipping.".format(call_site_addr))
                continue
                
            output_hv = output_vn.getHigh()
            if not output_hv:
                self.println("INFO: Call at {} has no HighVariable for its output. Nothing to taint. Skipping.".format(call_site_addr))
                continue

            current_initial_taint_source_hv_set = {output_hv}
            
            self.println("\n--- Initiating Taint Analysis for: {} (call at {}) ---".format(parent_func.getName(), call_site_addr))
            self.println("DEBUG: Taint source is the return value of the call: {}".format(self._get_varnode_representation(output_hv, high_parent_func)))

            self._trace_taint_in_function(
                high_parent_func, current_initial_taint_source_hv_set, target_call_op,
                originating_imported_func_name_for_log=str(target_keywords),
                current_depth=0,
                analysis_config={
                    'usage_types_to_report': self.default_usage_types_to_report
                },
                tainted_memory_regions=set() # Start with fresh memory regions
            )
    
        # --- Multi-Stage Analysis ---
        self.println("\n--- Stage 1 Complete. Checking for pending multi-stage analysis tasks... ---")
        processed_tasks = 0
        while self.pending_analysis_tasks:
            processed_tasks += 1
            task = self.pending_analysis_tasks.pop(0)
            task_origin = task.get('originating_imported_func_name_for_log', 'Unknown Rule')
            self.println("\n--- Initiating Stage 2 Analysis Task #{} (from rule: {}) ---".format(
                processed_tasks, task_origin
            ))
            
            # The key for visited_function_states includes the origin name, so we don't need to clear it.
            # This allows re-visiting a function if the taint comes from a different logical source.
            self._trace_taint_in_function(
                task['high_func_to_analyze'],
                task['initial_tainted_hvs'],
                task['pcode_op_start_taint'],
                task_origin,
                current_depth=0, # Start a fresh trace from depth 0
                analysis_config=task['analysis_config'],
                tainted_memory_regions=task.get('tainted_memory_regions') # Pass memory regions if available
            )
        
        if processed_tasks > 0:
            self.println("\n--- All Multi-Stage Analysis Tasks Complete. ---")
        else:
            self.println("--- No multi-stage analysis tasks were queued. ---")


        if not all_call_sites and not processed_tasks > 0: 
            self.println("INFO: No call sites processed for keywords '{}' and no multi-stage tasks run.".format(target_keywords))

        self.println("\n--- Taint Analysis Run Complete ---")
        if self.all_tainted_usages:
            self._print_results()
            self._save_results_to_json()
        else:
            self.println("No tainted value usages detected for keywords '{}'.".format(target_keywords))


# -------------------
# Main script entry point (Ghidra script boilerplate)
# -------------------
def run_analysis_from_ghidra_ui():
    """
    This function is the main entry point when run from Ghidra's UI.
    It sets up the environment and kicks off the analysis.
    This is a placeholder in the generic engine and should be implemented
    by the specific analyzer script that uses this engine.
    """
    _println = globals().get('println', lambda msg: sys.stdout.write(str(msg) + "\n"))
    _println("This is the generic taint analysis engine.")
    _println("It is not meant to be run directly.")
    _println("Please run a specific analysis script (e.g., mnn_analyzer.py) which uses this engine.")
    return


if __name__ == "__main__":
    if 'currentProgram' in globals() and globals().get('currentProgram') is not None:
        run_analysis_from_ghidra_ui()
    else:
        print("This script is designed to be run from within Ghidra's Script Manager.")
    
    _final_println = globals().get('println', lambda x: None)
    _final_println("analyze_mnn_taint_modular.py finished.") 