"""
Provides some miscellaneous helper functions
"""
def read_file_as_bytes(path:str) -> bytes:
    """
    Reads file as bytes and returns it.
    
    :param str path: Path to file to read as bytes.
    """
    with open(path,"rb") as file:
        data = file.read()
        return data

def read_file(path:str) -> str:
    """
    Reads text file as string and returns it.
    
    :param str path: Path to file to read as string.
    :return str: string containing the file text content.
    """
    with open(path,"r",encoding="utf-8") as file:
        data = file.read()
        return data

def write_bytes_to_file(path:str, data:bytes):
    """
    Writes bytes to file
    
    :param str path: Path to the file to either create or overwrite
    :param bytes data: The data to be written to the file
    """
    with open(path,"wb") as file:
        file.write(data)

def write_to_file(path:str, data:str):
    """
    Writes bytes to file
    
    :param str path: Path to the file to either create or overwrite
    :param str data: The data to be written to the file
    """
    with open(path,"w",encoding="utf-8") as file:
        file.write(data)
