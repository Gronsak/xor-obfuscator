"""
The main module for obfuscator.py
"""
import sys
import argparse
from enum import Enum
from os import path
from utils import read_file_as_bytes, write_bytes_to_file, write_to_file
from xor import xor_obfuscate
from output_formats import format_as_c_array, format_as_python

# Enum for internal representation of output format
OutputFormat = Enum("Formats", [("raw", 0),("C", 1),("Python",2)])

def print_status(msg: str,enabled: bool = True, output: bool = False):
    """Conditionally print **msg**, determined by the **enabled** parameter.
    
    :param str msg: Message string to be printed.
    :param bool enabled: (default: True) When False **msg** will not be printed.
    :param bool output: (default: False) When True print to stdout, otherwise print to stderr
    """
    if enabled is True:
        if output is True:
            print(msg, file=sys.stdout)
        elif output is False:
            print(msg, file=sys.stderr)

def handle_output(
        data:bytes,
        output_path:str|None,
        format_mode:OutputFormat,
        verbose:bool,
        terminal_output:bool) -> bool:
    """
    Helper function to handle final program output and print related status.
    
    :param bytes data: Data bytes to be output
    :param str|None output_path: Filepath to write output to, if None no file will be written
    :param Formats format_mode: How to format the output
    :param bool verbose: If output should be verbose (True) or not (False)
    :param bool terminal_output: If output should be printed to terminal (True) or not (False)
    :return bool: on error returns False, on success returns True
    """
    # Convert to requested output format only if needed
    if format_mode == OutputFormat.C:
        data = format_as_c_array(data)
    elif format_mode == OutputFormat.Python:
        data = format_as_python(data)

    # Ignore write functions if no output specified and
    # if obfuscated data is binary force a status message to stderr
    if output_path is not None:
        print_status(f"[+] Writing obfuscated data to: {output_path}",verbose)
        # Choose write function based on current object type (bytes vs str)
        try:
            if isinstance(data, bytes):
                write_bytes_to_file(output_path, data)
            elif isinstance(data, str):
                write_to_file(output_path, data)
        except IOError:
            print_status("[!] There was an error writing the file!\n"+
                "[X] Exiting!")
            return False
    elif isinstance(data, bytes):
        print_status("[+] Successfully obfuscated binary data!\n"+
                     "[!] No output in raw mode!\n"+
                     "    Run again with --output to save binary data")

    # If output was formatted as text display it when verbose or terminal flag
    # is set or if there is no output specified
    if isinstance(data, str):
        print_status(f"[+] {format_mode.name} formatted output:\n",verbose)
        if output_path is None:
            print_status(f"{data}\n",True, True)
        else:
            print_status(f"{data}\n",(verbose or terminal_output), True)
    return True

def create_parser() -> argparse.ArgumentParser:
    """
    Create the ArgumentParser to handle program arguments
    
    :return ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="A simple program that obfuscates raw shellcode " \
                    "using xor to avoid detection by antivirus software.",
        epilog="example usage, python obfuscator.py shellcode.bin -k 0x42 -o obfuscated_code.xor",
        formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("shellcodePath",
                        help="Path to shellcode binary file.")
    parser.add_argument("-f", "--force", "--overwrite",
                        action="store_true",
                        help="Skip overwrite prompt and always overwrite existing output file.")
    parser.add_argument("-k", "--key",
                        help="The key for the xor operation,\n" \
                            "KEY can be either as as a single byte formatted as HEX '0x42' or as " \
                            "a string 'example123'.",
                        required=True)
    parser.add_argument("-m", "--mode",
                        default="raw",
                        choices=["r","raw","c","c-array","p","python"],
                        help="Format mode for the output\n" \
                            "r, raw - raw binary output. (default)\n" \
                            "c, c-array - As a C/C++ array for use in C/C++ code.\n" \
                            "p, python - as a Python literal for use in Python code.")
    parser.add_argument("-o", "--output",
                        help="Output path for xor obfuscated shellcode.\n" \
                        "If omitted, raw mode will result in no output but program will still run.")
    parser.add_argument("-t", "--terminal",
                        action="store_true",
                        help="If possible show output data in terminal.")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Print status messages and if possible output data.")
    return parser

def main() -> int:
    """Main entrypoint for the CLI. Reads a binary shellcode file, 
    obfuscates the data and writes it to a file in formats and/or outputs it to the terminal.

    :return int: process exit code (0 success, 1 on error)
    """
    parser = create_parser()

    args = parser.parse_args()

    verbose = args.verbose
    terminal_output = args.terminal

    # Parse HEX input if string starts with "0x" otherwise convert string to bytes
    # Note: currently only supports single-byte hex like '0x42' because len==4 is checked.
    # key_mode variable is used to give user feedback if input was recognized as HEX
    if args.key.startswith("0x") and len(args.key) == 4:
        key = bytes.fromhex(args.key[2:])
        key_mode = "hex"
    else:
        key = bytes(args.key, "utf-8")
        key_mode = "string"

    format_input = args.mode.lower()

    match format_input:
        case "r"|"raw":
            format_mode = OutputFormat.raw
        case "c"|"c-array":
            format_mode = OutputFormat.C
        case "p"|"python":
            format_mode = OutputFormat.Python

    # Validate input path before continuing
    if not path.exists(args.shellcodePath):
        print_status(f"[!] Could not find file with path: {args.shellcodePath}\n"+
               "[X] Exiting!")
        return 1

    output_path = args.output

    # If output exists ask user unless --force specified
    # Keep prompting until valid answer received: explicit 'y' to continue
    if output_path is not None and path.exists(output_path) and args.force is not True:
        uinput = input(f"[!] File {output_path} already exists,\n"
                       +"    do you want to overwrite? (y/N): ").lower().strip()
        while True:
            match uinput:
                case "" | "n" | "no":
                    print_status("[-] File will not be overwritten. Exiting!")
                    return 1
                case "y" | "yes":
                    print_status("[+] File will be overwritten.", verbose)
                    break
            uinput = input("[-] Invalid answer! (y/N): ")

    # Read shellcode bytes; read_file_as_bytes raises IOError on failure -> handled below
    try:
        file = read_file_as_bytes(args.shellcodePath)
    except IOError:
        print_status("[!] There was an error reading the file!\n"+
              "[X] Exiting!")
        return 1

    # Report key runtime info only if verbose set
    print_status(f"[+] Input: {args.shellcodePath} ({len(file)}bytes)\n"+
          f"[+] Output: {output_path}\n"+
          f"[+] Format: {format_mode.name}\n"+
          f"[+] Key: {args.key} (mode:{key_mode})", verbose)

    # xor each data byte using key (implementation in xor.py)
    print_status("[+] Running xor operation...", verbose)
    obfuscated = xor_obfuscate(file,key)
    print_status(f"[+] New data length: {len(obfuscated)}bytes",verbose)

    success = handle_output(obfuscated, output_path, format_mode, verbose, terminal_output)
    if success is not True:
        return 1

    print_status("[+] Program finished!\n    Happy hacking!",verbose)
    return 0

if __name__ == '__main__':
    sys.exit(main())
