def read_file_as_bytes(path:str):
    with open(path,"rb") as file:
        data = file.read()
        return data

def read_file(path:str):
    with open(path,"r") as file:
        data = file.read()
        return data
    
def write_bytes_to_file(path:str, data:bytes):
    with open(path,"xb") as file:
        file.write(data)

def write_to_file(path:str, data:str):
    with open(path,"x") as file:
        file.write(data)