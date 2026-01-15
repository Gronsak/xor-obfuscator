def format_as_c_array(data:bytes) -> str:
    cstring = "unsigned char xor_shellcode[] = {\n    "
    i = 0
    c = 4
    for b in data:
        if i > 0:
            s = ", "
            cstring += s
            c += len(s)
        s = f"{b:#0{4}x}"
        cstring += s
        c += len(s)
        i += 1
        if c >= (80 - len(s) - 1):
            s = ",\n    "
            cstring += s
            c = len(s)
            i = 0
    cstring += "\n};"
    return cstring

def format_as_python(data:bytes) -> str:
    pstring = f"shellcode = b\"\"\n"
    i = 0
    c = 0
    for b in data:
        if i == 0:
            s = "shellcode += b\""
            pstring += s
            c += len(s)

        s = f"\\x{b:0{2}x}"
        pstring += s
        c += len(s)

        i += 1
        if c >= (80 - len(s) - 1):
            s = "\"\n"
            pstring += s
            c = 0
            i = 0
    pstring += "\""
    return pstring


