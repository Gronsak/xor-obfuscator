def format_as_c_array(data:bytes) -> str:
    cstring = "unsigned char xor_shellcode[] = {\n"
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
