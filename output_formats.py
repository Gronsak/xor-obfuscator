def format_as_c_array(data:bytes) -> str:
    """Formats the input **data** as a C/C++ char array with the data and returns it as a string with linebreaks that can be pasted into C/C++ code.

    :param bytes data: bytes to be converted and formated
    :return str: a formated string containing a C/C++ char array containing the data

    **example string**:
    ```
    unsigned char xored_shellcode[] = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb
    };
    ```
    """
    cstring = "unsigned char xored_shellcode[] = {\n"
    linestart = True
    charLen = 0
    for b in data:
        s = ""
        if linestart is not True:
            s += ", "
        elif linestart is True:
            s += "    "
        s += f"{b:#0{4}x}"
        cstring += s
        charLen += len(s)
        linestart = False
        if charLen >= (80 - len(s) - 1):
            cstring += ",\n"
            charLen = 0
            linestart = True
    cstring += "\n};"
    return cstring

def format_as_python(data:bytes) -> str:
    """Formats the input **data** as a Python literal b"" converted to HEX and returns it as a string with linebreaks that can be pasted into Python code.

    :param bytes data: bytes to be converted and formated
    :return str: a formated string containing a Python literal b"" with the data
    
    **example string**:
    ```
    shellcode = b""
    shellcode += b"\\xaa\\xbb\\xcc\\xdd\\xee\\xff\\x11\\x22\\x33\\x44\\x55\\x66\\x77\\x88\\x99"
    shellcode += b"\\xaa\\xbb\\xcc\\xdd\\xee\\xff\\x11\\x22\\x33\\x44\\x55\\x66\\x77\\x88\\x99"
    shellcode += b"\\x11\\x22\\x33\\x44"
    ```
    """
    pstring = f"shellcode = b\"\"\n"
    linestart = True
    charLen = 0
    for b in data:
        s = ""
        if linestart is True:
            s = "shellcode += b\""

        s += f"\\x{b:0{2}x}"
        pstring += s
        charLen += len(s)

        linestart = False
        if charLen >= (80 - len(s) - 1):
            pstring += "\"\n"
            charLen = 0
            linestart = True
    pstring += "\""
    return pstring
