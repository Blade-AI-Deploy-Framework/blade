# gdb_script_host.py
# This script runs inside GDB to set breakpoints and print register values.
# It's designed to be run in GDB's batch mode and reads config from environment variables.

import gdb
import json
import os
import struct

def is_hex_float(s):
    """
    Checks if a string is a hex representation of a 32-bit float.
    e.g., '0x3f800000'
    """
    if not isinstance(s, str) or not s.startswith('0x'):
        return False
    try:
        # Must be 0x + 8 hex characters for a 32-bit float
        if len(s) == 10:
            int(s, 16)
            return True
    except ValueError:
        return False
    return False

def hex_to_float(hex_str):
    """
    Converts a hex string representing a 32-bit float to a Python float.
    """
    return struct.unpack('!f', struct.pack('!I', int(hex_str, 16)))[0]

class HookBreakpoint(gdb.Breakpoint):
    """
    Custom breakpoint that prints register values in a machine-readable format.
    """
    def __init__(self, address_str, relative_addr_str, registers_to_watch):
        super(HookBreakpoint, self).__init__(address_str, gdb.BP_BREAKPOINT, internal=True)
        self.registers = registers_to_watch
        self.address_str = address_str
        self.relative_addr_str = relative_addr_str

    def stop(self):
        """
        When the breakpoint is hit, print the values and continue.
        """
        try:
            frame_info_str = gdb.execute("info frame", to_string=True).strip()
            print(f"[GDB HOOK INFO]\n{frame_info_str}")
        except gdb.error:
            print("[GDB HOOK INFO] Could not retrieve frame information.")
        
        for item in self.registers:
            try:
                if item.startswith(('x', 's', 'w', 'd')):
                    value = gdb.parse_and_eval(f"${item}")
                    print(f"HOOK_RESULT: offset={self.relative_addr_str} address={self.address_str} register={item} value={value}")
                elif is_hex_float(item):
                    value = hex_to_float(item)
                    print(f"HOOK_RESULT: offset={self.relative_addr_str} address={self.address_str} immediate_float={item} value={value}")
                else:
                    value = gdb.parse_and_eval(item)
                    print(f"HOOK_RESULT: offset={self.relative_addr_str} address={self.address_str} immediate={item} value={value}")
            except gdb.error as e:
                # Instead of a warning, print a machine-readable error.
                # Sanitize the error message to remove quotes that could break parsing.
                reason = str(e).replace('"', "'")
                print(f'HOOK_ERROR: offset={self.relative_addr_str} register={item} reason="{reason}"')
        
        return False

def load_hooks(hooks_path):
    """
    Loads hook definitions from a specified JSON file path.
    """
    if not os.path.exists(hooks_path):
        print(f"[GDB SCRIPT ERROR] Hooks file not found at: {hooks_path}")
        return []
    try:
        with open(hooks_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[GDB SCRIPT ERROR] Failed to parse {hooks_path}: {e}")
        return []

def get_base_address():
    """
    Finds the base address of the main executable in GDB after it has been loaded.
    """
    try:
        mappings_str = gdb.execute("info proc mappings", to_string=True)
        prog_path = gdb.current_progspace().filename

        for line in mappings_str.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[-1] == prog_path:
                base_address = int(parts[0], 16)
                print(f"[GDB SCRIPT INFO] Found base address for {prog_path}: {hex(base_address)}")
                return base_address
        
        print(f"[GDB SCRIPT ERROR] Could not find memory mapping for '{prog_path}'.")
        return None
    except gdb.error as e:
        print(f"[GDB SCRIPT ERROR] Failed to get base address: {e}")
        return None

def set_breakpoints(base_address, hooks_path):
    """
    Sets all breakpoints defined in the hooks file, adjusting for base address.
    """
    hooks = load_hooks(hooks_path)
    if not hooks:
        return
    
    if not isinstance(hooks, list):
        hooks = [hooks]

    gdb.execute("delete breakpoints")
    for hook in hooks:
        try:
            # Adapt to potentially nested 'registers' format in JSON
            raw_registers = hook.get('registers', [])
            registers_to_watch = []
            if raw_registers and isinstance(raw_registers[0], dict):
                # New format: [{"register": "x0"}, {"register": "x1"}]
                registers_to_watch = [item['register'] for item in raw_registers]
            else:
                # Original format: ["x0", "x1"]
                registers_to_watch = raw_registers
            
            # --- Filter out hooks with complex references ---
            should_ignore = any("StackDirect" in r or "UniquePcode" in r for r in registers_to_watch)
            if should_ignore:
                print(f"[GDB SCRIPT INFO] Ignoring hook at {hook.get('address')} due to unsupported reference (StackDirect/UniquePcode).")
                continue # Skip this hook entirely

            relative_addr = int(hook['address'], 16)
            absolute_addr = base_address + relative_addr

            HookBreakpoint(f"*{hex(absolute_addr)}", hook['address'], registers_to_watch)
            print(f"[GDB SCRIPT INFO] Set breakpoint at {hex(absolute_addr)} (base {hex(base_address)} + offset {hook['address']}) for registers {registers_to_watch}")
        
        except Exception as e:
            print(f"[GDB SCRIPT ERROR] Failed to set breakpoint for hook {hook}: {e}")

# --- Main execution logic for the script ---

# The path to the hooks file is passed via an environment variable
# set by the runner script. This is more reliable than parsing argv.
try:
    HOOKS_FILE_PATH = os.getenv("HOOKS_JSON_PATH")
    if not HOOKS_FILE_PATH:
        raise ValueError("Environment variable 'HOOKS_JSON_PATH' is not set or is empty.")
    if not os.path.exists(HOOKS_FILE_PATH):
         raise FileNotFoundError(f"Hooks file specified by HOOKS_JSON_PATH does not exist: {HOOKS_FILE_PATH}")

    print(f"[GDB SCRIPT INFO] Using hooks file from env var: {HOOKS_FILE_PATH}")

except (ValueError, FileNotFoundError) as e:
    print(f"[GDB SCRIPT ERROR] Could not get hooks file path: {e}")
    HOOKS_FILE_PATH = None


# Start the program, but stop at the first instruction.
# This loads the executable into memory so we can find its base address.
gdb.execute("starti")

# Get the base address now that the process is mapped in memory.
base_addr = get_base_address()

if base_addr is not None and HOOKS_FILE_PATH is not None:
    # Set the breakpoints using the calculated base address.
    set_breakpoints(base_addr, HOOKS_FILE_PATH)

# Continue program execution.
# GDB will stop at our breakpoints, execute the `stop` method, and then continue.
gdb.execute("continue") 