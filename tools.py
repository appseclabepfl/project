import hashlib

BUFFER_SIZE = 1024

# hash a file using sha256
# return the hash digest (bytes)
def hash_file(path):

    file_hash = hashlib.sha256() 

    with open(path, 'rb') as f: 

        fb = f.read(BUFFER_SIZE) 
        while fb: 
            file_hash.update(fb) 
            fb = f.read(BUFFER_SIZE) 

        return file_hash.digest()


# hash bytes using sha256
# return the hash digest (bytes)
def hash_bytes(b):

    file_hash = hashlib.sha256() 
    file_hash.update(b)

    return file_hash.digest()