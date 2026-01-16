import sys
import argparse
from enum import Enum
from os import path
from utils import read_file_as_bytes, write_bytes_to_file, write_to_file
from xor import xor_obfuscate
from output_formats import format_as_c_array, format_as_python

def print_status(msg:str,enabled:bool = True):
    if enabled is True:
        print(msg)

def main() -> int:
    parser = argparse.ArgumentParser(
        prog="xor Obfuscator", 
        description="A simple program that obfuscates raw shellcode using xor to aviod detection by antivirus software.",
        epilog="example usage, 'python obfuscator.py -k 0x42 -f c shellcode.bin obfuscated_code.xor'",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("shellcodePath", 
                        help="Path to shellcode binary file.")
    parser.add_argument("outputPath", 
                        help="Output path for xor obfuscated shellcode.")
    parser.add_argument("-m", "--mode", 
                        default="raw", 
                        choices=["r","raw","c","c-array","p","python"],
                        help="Format of the output\nr,raw - raw binary output. (default)\nc,c-array - As a C/C++ array for use in C/C++ code.\np,python - as a Python literal for use in Python code.")
    parser.add_argument("-k", "--key",
                        help="The key for the xor operation,\ncan be either as as a hex byte formated as '0x42' or as a string 'example123'.",
                        required=True)
    parser.add_argument("-f", "--force", "--overwrite",
                        action="store_true",
                        help="Skip overwrite prompt and always overwrite existing output file.")
    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Print status messages and output data, if possible, while running the program.")
    parser.add_argument("-t", "--terminal",
                        action="store_true",
                        help="If possible show output data in terminal.")

    args = parser.parse_args()

    verbose = args.verbose
    terminalOutput = args.terminal

    key = b""
    keyMode = ""
    if args.key.startswith("0x") and len(args.key) == 4:
        key = bytes.fromhex(args.key[2:])
        keyMode = "hex"
    else :
        key = bytes(args.key, "utf-8")
        keyMode = "string"

    formatInput = args.mode.lower()
    Format = Enum("Formats", [("raw", 0),("C", 1),("Python",2)])

    formatMode = Format.raw
    if formatInput == "r" or formatInput == "raw":
        formatMode = Format.raw
    elif formatInput == "c" or formatInput == "c-array":
        formatMode = Format.C
    elif formatInput == "p" or formatInput == "python":
        formatMode = Format.Python
    
    if not path.exists(args.shellcodePath):
        print(f"[!] Could not find file with path: {args.shellcodePath}\n"+
               "[X] Exiting!")
        return 1
    
    # TODO: handle overwrite
    if path.exists(args.outputPath) and args.force is not True:
        uinput = input(f"[!] File {args.outputPath} already exists,\ndo you want to overwrite? (y/N): ").lower().strip()
        while True:
            if uinput == "n" or uinput == "":
                print("[-] File will not be overwriten. Exiting!")
                return 1
            elif uinput == "y":
                print_status("[+] File will be overwriten.", verbose)
                break
            else:
                uinput = input("[-] Invalid input, answer with 'y' or 'n'! (y/N): ")
        
    outPath = args.outputPath
    
    try:
        file = read_file_as_bytes(args.shellcodePath)
    except IOError:
        print_status("[!] There was an error reading the file!\n"+
              "[X] Exiting!")
        return 1

    print_status(f"[+] Input: {args.shellcodePath} ({len(file)}bytes)\n"+
          f"[+] Output: {outPath}\n"+
          f"[+] Format: {formatMode.name}\n"+
          f"[+] Key: {args.key} (mode:{keyMode})", verbose)
    
    print_status("[+] Running xor operation...", verbose)
    obfuscated = xor_obfuscate(file,key)
    print_status(f"[+] New data length: {len(obfuscated)}bytes",verbose)
    
    if formatMode == Format.C:
        obfuscated = format_as_c_array(obfuscated)
    elif formatMode == Format.Python:
        obfuscated = format_as_python(obfuscated)

    print_status(f"[+] Writing obfuscated data to: {outPath}",verbose)
    try:
        if isinstance(obfuscated, bytes):
            write_bytes_to_file(outPath, obfuscated)
        elif isinstance(obfuscated, str):
            write_to_file(outPath, obfuscated)
    except IOError:
        print("[!] There was an error writing the file!\n"+
              "[X] Exiting!")
        return 1
    if isinstance(obfuscated, str):
        print_status(f"[+] {formatMode.name} formated output:\n",verbose)
        print_status(f"{obfuscated}\n",(verbose or terminalOutput))
    
    print_status("[+] Program finished! Happy hacking!",verbose)
    return 0

if __name__ == '__main__':
    sys.exit(main())