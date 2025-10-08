import json
import argparse
import os

def filter_hook_config(input_file_path, output_file_path):
    """
    Reads a hook config, filters out entries with registers containing
    'UniquePcode' or 'Stack', and writes the result to a new file.
    """
    try:
        with open(input_file_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("Error: Input file not found at '{}'".format(input_file_path))
        return
    except json.JSONDecodeError:
        print("Error: Could not decode JSON from the input file '{}'".format(input_file_path))
        return

    filtered_data = []
    removed_count = 0

    for entry in data:
        should_remove = False
        if 'registers' in entry and isinstance(entry['registers'], list):
            for reg_info in entry['registers']:
                register_value = reg_info.get('register', '')
                if 'UniquePcode' in register_value or 'Stack' in register_value:
                    should_remove = True
                    break  # No need to check other registers in this entry
        
        if not should_remove:
            filtered_data.append(entry)
        else:
            removed_count += 1
            print("Removing entry for address {}: Found disallowed register.".format(entry.get('address', 'N/A')))

    try:
        # Ensure the output directory exists
        output_dir = os.path.dirname(output_file_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            
        with open(output_file_path, 'w') as f:
            json.dump(filtered_data, f, indent=4)
        
        print("\nFiltering complete.")
        print("Successfully wrote filtered data to '{}'".format(output_file_path))
        print("Total entries kept: {}".format(len(filtered_data)))
        print("Total entries removed: {}".format(removed_count))

    except IOError as e:
        print("Error: Could not write to output file '{}': {}".format(output_file_path, e))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Filter a Ghidra hook config JSON file to remove entries with specific register patterns."
    )
    parser.add_argument(
        'input_file',
        help="Path to the input hook config JSON file (e.g., results/face_analysis_cli_hook_config.json)."
    )
    parser.add_argument(
        '-o', '--output_file',
        help="Path for the filtered output JSON file. If not provided, it will be generated based on the input filename."
    )
    args = parser.parse_args()

    # Determine output file path if not provided
    if args.output_file:
        output_path = args.output_file
    else:
        # Create a default output name like 'input_filename_filtered.json'
        base, ext = os.path.splitext(args.input_file)
        output_path = "{}_filtered{}".format(base, ext)

    filter_hook_config(args.input_file, output_path)
