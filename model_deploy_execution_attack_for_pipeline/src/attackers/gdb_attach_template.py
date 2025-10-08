# gdb_attach_template.py
# This is a GDB Python script template designed to attach to a running process,
# find the base address of a specific shared library, and set breakpoints based on a hooks file.
# It is populated by a host script (e.g., frida_gdb_orchestrator.py).

import gdb
import json
import os
import struct

# --- Placeholder values to be replaced by the orchestrator ---
PORT_TO_CONNECT = "PLACEHOLDER_PORT"
HOOKS_JSON_STR = "PLACEHOLDER_HOOK_CONFIG_JSON_STR"
BASE_ADDRESS_SYMBOL = "PLACEHOLDER_BASE_ADDRESS_SYMBOL"

# --- Utility Functions (similar to gdb_script_host.py) ---

def is_hex_float(s):
    """Checks if a string is a hex representation of a 32-bit float."""
    if not isinstance(s, str) or not s.startswith('0x'):
        return False
    try:
        return len(s) == 10 and int(s, 16) is not None
    except ValueError:
        return False

def hex_to_float(hex_str):
    """Converts a hex string representing a 32-bit float to a Python float."""
    return struct.unpack('!f', struct.pack('!I', int(hex_str, 16)))[0]

class HookBreakpoint(gdb.Breakpoint):
    """Custom breakpoint that prints register values in a machine-readable format."""
    def __init__(self, address_str, relative_addr_str, registers_to_watch):
        super(HookBreakpoint, self).__init__(address_str, gdb.BP_BREAKPOINT, internal=True)
        self.registers = registers_to_watch
        self.address_str = address_str
        self.relative_addr_str = relative_addr_str

    def stop(self):
        """When the breakpoint is hit, print the values and continue."""
        print("[GDB HOOK TRIGGERED] at address {} (offset {})".format(self.address_str, self.relative_addr_str))
        for item in self.registers:
            try:
                if item.startswith(('x', 's', 'w', 'd')):
                    value = gdb.parse_and_eval("${}".format(item))
                    print("HOOK_RESULT: offset={} address={} register={} value={}".format(self.relative_addr_str, self.address_str, item, value))
                elif is_hex_float(item):
                    value = hex_to_float(item)
                    print("HOOK_RESULT: offset={} address={} immediate_float={} value={}".format(self.relative_addr_str, self.address_str, item, value))
                else:
                    value = gdb.parse_and_eval(item)
                    print("HOOK_RESULT: offset={} address={} immediate={} value={}".format(self.relative_addr_str, self.address_str, item, value))
            except gdb.error as e:
                reason = str(e).replace('"', "'")
                print('HOOK_ERROR: offset={} register={} reason="{}"'.format(self.relative_addr_str, item, reason))
        return False

def load_hooks_from_string(hooks_json_str):
    """Loads hook definitions from a JSON string."""
    try:
        return json.loads(hooks_json_str)
    except Exception as e:
        print("[GDB SCRIPT ERROR] Failed to parse hooks JSON string: {}".format(e))
        return []

def get_library_base_address(library_name):
    """
    Finds the base address of a loaded shared library in the attached process.
    """
    try:
        mappings_str = gdb.execute("info proc mappings", to_string=True)
        for line in mappings_str.splitlines():
            parts = line.split()
            # Check if the line has enough parts and the last part ends with the library name
            if len(parts) >= 5 and parts[-1].endswith("/{}".format(library_name)):
                base_address = int(parts[0], 16)
                print("[GDB SCRIPT INFO] Found base address for {}: {}".format(library_name, hex(base_address)))
                return base_address
        
        print("[GDB SCRIPT ERROR] Could not find memory mapping for '{}'.".format(library_name))
        return None
    except gdb.error as e:
        print("[GDB SCRIPT ERROR] Failed to get base address for {}: {}".format(library_name, e))
        return None

def set_breakpoints(base_address, hooks_json_str):
    """Sets all breakpoints defined in the hooks JSON string."""
    hooks = load_hooks_from_string(hooks_json_str)
    if not hooks:
        return

    if not isinstance(hooks, list):
        hooks = [hooks]

    gdb.execute("delete breakpoints")
    for hook in hooks:
        try:
            # This logic is adapted from gdb_script_host.py to handle different register formats
            raw_registers = hook.get('registers', [])
            registers_to_watch = [item['register'] for item in raw_registers if isinstance(item, dict)] if raw_registers and isinstance(raw_registers[0], dict) else raw_registers
            
            should_ignore = any("StackDirect" in r or "UniquePcode" in r for r in registers_to_watch)
            if should_ignore:
                print("[GDB SCRIPT INFO] Ignoring hook at {} due to unsupported reference.".format(hook.get('address')))
                continue

            relative_addr = int(hook['address'], 16)
            absolute_addr = base_address + relative_addr

            HookBreakpoint("*{}".format(hex(absolute_addr)), hook['address'], registers_to_watch)
            print("[GDB SCRIPT INFO] Set breakpoint at {} for registers {}".format(hex(absolute_addr), registers_to_watch))
        
        except Exception as e:
            print("[GDB SCRIPT ERROR] Failed to set breakpoint for hook {}: {}".format(hook, e))

# --- GDB Event Handling ---

def stop_handler(event):
    """GDB event handler for when the target program stops."""
    # We are only interested in signals, not our custom breakpoints.
    if isinstance(event, gdb.SignalEvent):
        # Use event.stop_signal for compatibility with older GDB Python APIs.
        signal_name = str(event.stop_signal)
        print("\n[GDB SCRIPT SIGNAL] Target received signal: {}".format(signal_name))
        # If the process is aborting, print the backtrace to find out why.
        if signal_name == 'SIGABRT':
            print("[GDB SCRIPT BACKTRACE] SIGABRT detected. Dumping call stack:")
            try:
                gdb.execute("bt")
            except gdb.error as e:
                print("[GDB SCRIPT ERROR] Could not retrieve backtrace: {}".format(str(e)))
            # The program has crashed, so we can detach and quit.
            gdb.execute("detach")
            gdb.execute("quit")

# --- Main GDB Script Execution ---

def main():
    if not HOOKS_JSON_STR or not PORT_TO_CONNECT or not BASE_ADDRESS_SYMBOL:
        print("[GDB SCRIPT ERROR] One or more placeholder values were not replaced.")
        return

    try:
        port = int(PORT_TO_CONNECT)
        print("[GDB SCRIPT INFO] Connecting to remote gdbserver on localhost:{}".format(port))
        gdb.execute("target remote :{}".format(port), to_string=True)
        print("[GDB SCRIPT INFO] Successfully connected to remote target.")
    except Exception as e:
        print("[GDB SCRIPT ERROR] Failed to connect to remote target on port {}: {}".format(port, e))
        gdb.execute("quit")
        return

    # Register the event handler to catch signals like SIGABRT.
    gdb.events.stop.connect(stop_handler)
    print("[GDB SCRIPT INFO] Registered stop handler for signal detection.")

    # Find the base address of the target library.
    base_addr = get_library_base_address(BASE_ADDRESS_SYMBOL)

    if base_addr is not None:
        # Set the breakpoints.
        set_breakpoints(base_addr, HOOKS_JSON_STR)
        # Continue program execution.
        print("[GDB SCRIPT READY]")
        print("[GDB SCRIPT INFO] Resuming process execution...")
        gdb.execute("continue")
        print("[GDB SCRIPT INFO] Process is running. Waiting for hooks...")
    else:
        print("[GDB SCRIPT ERROR] Could not determine base address. No breakpoints were set.")
        gdb.execute("detach")
        gdb.execute("quit")

# Run the main function
main()