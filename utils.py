def read_file_as_bytes(path):
    with open(path,"rb") as file:
        data = file.read()
        return data
    
def write_bytes_to_file(path, data):
    with open(path,"xb") as file:
        file.write(data)

def write_to_file(path, data):
    with open(path,"xb") as file:
        file.write(data)