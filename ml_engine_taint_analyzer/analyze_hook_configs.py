import json
import os
from pathlib import Path

def analyze_hook_config(file_path):
    """
    Analyzes a single hook_config.json file.

    Args:
        file_path (Path): The path to the JSON file.

    Returns:
        tuple: A tuple containing (total_addresses, simple_register_addresses_count).
               Returns (0, 0) if the file is invalid.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        print(f"Warning: Could not decode JSON or find file: {file_path}")
        return 0, 0

    if not isinstance(data, list):
        return 0, 0

    total_addresses = len(data)
    
    addresses_with_simple_registers = set()

    for item in data:
        if "address" not in item or "registers" not in item:
            continue
        
        address = item["address"]
        registers = item["registers"]

        if not isinstance(registers, list):
            continue

        for reg in registers:
            if "register" in reg and isinstance(reg["register"], str):
                if '(' not in reg["register"] and ')' not in reg["register"]:
                    addresses_with_simple_registers.add(address)
                    break # Found one, no need to check other registers for this address

    return total_addresses, len(addresses_with_simple_registers)

def main():
    """
    Main function to find and analyze all relevant hook_config.json files.
    """
    base_results_dir = Path("results")
    target_dirs = [base_results_dir / "clang", base_results_dir / "gcc"]
    
    print("--- Hook Config Analysis ---")

    for directory in target_dirs:
        if not directory.is_dir():
            print(f"Directory not found, skipping: {directory}")
            continue

        print(f"\nAnalyzing files in: {directory}/\n")
        
        hook_files = sorted(directory.rglob("*_hook_config.json"))

        if not hook_files:
            print("No hook_config.json files found.")
            continue

        for file_path in hook_files:
            total, simple_count = analyze_hook_config(file_path)
            relative_path = file_path.relative_to(base_results_dir)
            print(f"File: {relative_path}")
            print(f"  - Total 'address' count: {total}")
            print(f"  - Addresses with simple registers (no '()'): {simple_count}")
            print("-" * 20)

    print("\n--- Analysis Complete ---")


if __name__ == "__main__":
    main()





