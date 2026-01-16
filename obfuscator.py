import sys
import argparse
from enum import Enum
from os import path
from utils import read_file_as_bytes, write_bytes_to_file, write_to_file
from xor import xor_obfuscate
from output_formats import format_as_c_array, format_as_python

# Simple function for filtering output based on boolean input
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

def main() -> int:
    """Main entrypoint for the CLI. Reads a binary shellcode file, obfuscates the data and writes it to a file in formats and/or outputs it to the terminal.

    :return int: process exit code (0 success, 1 on error)
    """
    parser = argparse.ArgumentParser(
        prog="xor Obfuscator",
        description="A simple program that obfuscates raw shellcode using xor to avoid detection by antivirus software.",
        epilog="example usage, 'python obfuscator.py -k 0x42 -f c shellcode.bin obfuscated_code.xor'",
        formatter_class=argparse.RawTextHelpFormatter)
    
    parser.add_argument("shellcodePath",
                        help="Path to shellcode binary file.")
    parser.add_argument("-f", "--force", "--overwrite",
                        action="store_true",
                        help="Skip overwrite prompt and always overwrite existing output file.")
    parser.add_argument("-k", "--key",
                        help="The key for the xor operation,\nKEY can be either as as a single byte formated as HEX '0x42' or as a string 'example123'.",
                        required=True)
    parser.add_argument("-m", "--mode",
                        default="raw",
                        choices=["r","raw","c","c-array","p","python"],
                        help="Format of the output\nr,raw - raw binary output. (default)\nc,c-array - As a C/C++ array for use in C/C++ code.\np,python - as a Python literal for use in Python code.")
    parser.add_argument("-o", "--output",
                        help="Output path for xor obfuscated shellcode.\nIf omited, raw mode will result in no output but program will still run.")
    parser.add_argument("-t", "--terminal",
                        action="store_true",
                        help="If possible show output data in terminal.")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Print status messages and output data, if possible, while running the program.")

    args = parser.parse_args()

    verbose = args.verbose
    terminalOutput = args.terminal

    key = b""
    # keyMode variable is used to give user feedback if input was recognized as HEX
    keyMode = ""
    # Parse HEX input if string starts with "0x" otherwise convert string to bytes with utf-8 encoding
    # Note: currently only supports single-byte hex like '0x42' because len==4 is checked.
    if args.key.startswith("0x") and len(args.key) == 4:
        key = bytes.fromhex(args.key[2:])
        keyMode = "hex"
    else:
        # Treat any other input as UTF-8 strings (multi-byte key supported)
        key = bytes(args.key, "utf-8")
        keyMode = "string"

    formatInput = args.mode.lower()
    # Use an Enum for clear internal representation of output format
    Format = Enum("Formats", [("raw", 0),("C", 1),("Python",2)])

    formatMode = Format.raw
    if formatInput == "r" or formatInput == "raw":
        formatMode = Format.raw
    elif formatInput == "c" or formatInput == "c-array":
        formatMode = Format.C
    elif formatInput == "p" or formatInput == "python":
        formatMode = Format.Python
    
    # Validate input path early to provide fast feedback
    if not path.exists(args.shellcodePath):
        print_status(f"[!] Could not find file with path: {args.shellcodePath}\n"+
               "[X] Exiting!")
        return 1
    
    outPath = args.output
    # If output exists ask user unless --force specified
    if outPath is not None and path.exists(outPath) and args.force is not True:
        uinput = input(f"[!] File {outPath} already exists,\ndo you want to overwrite? (y/N): ").lower().strip()
        # Keep prompting until valid answer received: explicit 'y' to continue
        while True:
            if uinput == "n" or uinput == "":
                print_status("[-] File will not be overwriten. Exiting!")
                return 1
            elif uinput == "y":
                print_status("[+] File will be overwriten.", verbose)
                break
            else:
                uinput = input("[-] Invalid input, answer with 'y' or 'n'! (y/N): ")
    
    # Read shellcode bytes; read_file_as_bytes raises IOError on failure -> handled below
    try:
        file = read_file_as_bytes(args.shellcodePath)
    except IOError:
        print_status("[!] There was an error reading the file!\n"+
              "[X] Exiting!")
        return 1

    # Report key runtime info only if verbose set
    print_status(f"[+] Input: {args.shellcodePath} ({len(file)}bytes)\n"+
          f"[+] Output: {outPath}\n"+
          f"[+] Format: {formatMode.name}\n"+
          f"[+] Key: {args.key} (mode:{keyMode})", verbose)
    
    print_status("[+] Running xor operation...", verbose)
    # Core transformation: xor each byte with key (implementation in xor.py)
    obfuscated = xor_obfuscate(file,key)
    print_status(f"[+] New data length: {len(obfuscated)}bytes",verbose)
    
    # Convert to requested output format only if needed
    if formatMode == Format.C:
        obfuscated = format_as_c_array(obfuscated)
    elif formatMode == Format.Python:
        obfuscated = format_as_python(obfuscated)

    # Ignore write functions if no output specified and if obfuscated data is binary force a status message to stderr
    if outPath is not None:
        print_status(f"[+] Writing obfuscated data to: {outPath}",verbose)
        # Choose write function based on current object type (bytes vs str)
        try:
            if isinstance(obfuscated, bytes):
                write_bytes_to_file(outPath, obfuscated)
            elif isinstance(obfuscated, str):
                write_to_file(outPath, obfuscated)
        except IOError:
            print_status("[!] There was an error writing the file!\n"+
                "[X] Exiting!")
            return 1
    elif isinstance(obfuscated, bytes):
        print_status("[+] Successfully obfuscated binary data!\n[!] No output in raw mode!\n    Run again with --output to save binary data")

    # If output was formatted as text display it when verbose or terminal flag is set or if there is no output specified
    if isinstance(obfuscated, str):
        print_status(f"[+] {formatMode.name} formated output:\n",verbose)
        if outPath is None:
            print_status(f"{obfuscated}\n",True, True)
        else:
            print_status(f"{obfuscated}\n",(verbose or terminalOutput), True)
    
    print_status("[+] Program finished! Happy hacking!",verbose)
    return 0

if __name__ == '__main__':
    sys.exit(main())