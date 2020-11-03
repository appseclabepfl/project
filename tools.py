import hashlib
import os
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

BUFFER_SIZE = 1024
KEY_BYTE_LENGTH = 32 #corresponds to 256 bits
IV_BYTE_LENGTH = 16

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


#perform rounds of hash
def hash_rounds(b, n):

    hash = b

    for i in  range(0,n):

        hash = hash_bytes(hash)

    return hash


#encrypt data using a key with aes-ctr
#returns the encrypted data with the IV as prefix

def encrypt(key_path, data):

    f = open(key_path, 'rb')
    key = f.read(KEY_BYTE_LENGTH)
    
    random_generator = Random.new()
    iv = random_generator.read(IV_BYTE_LENGTH)

    ctr = Counter.new(128, prefix=iv)

    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    f.close()

    return iv + aes.encrypt(data)


#decryption function
def decrypt(key_path, data):

    iv = data[0:IV_BYTE_LENGTH -1]
    encrypted_data = data[IV_BYTE_LENGTH:]

    f = open(key_path, 'rb')
    key = f.read(KEY_BYTE_LENGTH)

    ctr = Counter.new(128, prefix=iv)

    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    f.close()

    return aes.decrypt(encrypted_data)

