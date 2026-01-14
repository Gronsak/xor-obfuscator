def read_file_as_bytes(path):
    with open(path,"rb") as file:
        data = file.read()
        return data