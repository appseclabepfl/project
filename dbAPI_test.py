#!/usr/bin/python
import socket
import base64
import hashlib
import json
import ssl

DB_IP = '192.168.56.101'
port = 42069
CHECK_PASSWORD = 'CHECK_PASSWORD'
GET_USER_DATA = 'GET_USER_DATA'
UPDATE_USER_DATA = 'UPDATE_USER_DATA'
username = 'a3'
pwd_clear = 'Astrid'

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.verify_mode = ssl.CERT_REQUIRED
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/simon/Documents/EPFL/Master/MA3/Applied Security Lab/project_keys/test/local_TLS.pem', '/home/simon/Documents/EPFL/Master/MA3/Applied Security Lab/project_keys/test/local_TLS.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/simon/Documents/EPFL/Master/MA3/Applied Security Lab/project_keys/test/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')

## CHECK PASSWORD TEST
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock)
ssock.connect((DB_IP, port))
ssock.send(CHECK_PASSWORD.encode())
print(ssock.recv(1024).decode())
hashed = hashlib.sha1(pwd_clear).hexdigest()
ssock.send(base64.b64encode(username+":"+hashed).encode())
print(ssock.recv(1024).decode())
ssock.close()
print("#######################################################")
## GET USER DATA TEST EXISTING USER
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock)
ssock.connect((DB_IP, port))
ssock.send(GET_USER_DATA.encode())
print(ssock.recv(1024).decode())
ssock.send(base64.b64encode(username).encode())
response = json.loads(ssock.recv(1024))
print(response["uid"])
print(response["lastname"])
print(response["firstname"])
print(response["email"])
print(response["response_code"])
print(response["error_msg"])
ssock.close()
print("#######################################################")
## GET USER DATA TEST NON EXISTING USER
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock)
ssock.connect((DB_IP, port))
ssock.send(GET_USER_DATA.encode())
print(ssock.recv(1024).decode())
ssock.send(base64.b64encode("dummy").encode())
response = json.loads(ssock.recv(1024))
print(response["response_code"])
print(response["error_msg"])
ssock.close()
print("#######################################################")
## UPDATE EMAIL ADDRESS AND ROLLBACK
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock)
ssock.connect((DB_IP, port))
ssock.send(UPDATE_USER_DATA.encode())
print(ssock.recv(1024).decode())
json_payload = {
    "uid": "a3", "lastname": "Anderson",
    "firstname": "Andres Andrea", "email": "updated@email.ch",
    "pwd": ""
}
ssock.send(json.dumps(json_payload).encode())
print(ssock.recv(1024).decode())
ssock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock)
ssock.connect((DB_IP, port))
ssock.send(GET_USER_DATA.encode())
print(ssock.recv(1024).decode())
ssock.send(base64.b64encode(username).encode())
response = json.loads(ssock.recv(1024))
print(response["uid"])
print(response["lastname"])
print(response["firstname"])
print(response["email"])
print(response["response_code"])
print(response["error_msg"])
ssock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssock = context.wrap_socket(sock)
ssock.connect((DB_IP, port))
ssock.send(UPDATE_USER_DATA.encode())
print(ssock.recv(1024).decode())
json_payload = {
    "uid": "a3", "lastname": "Anderson",
    "firstname": "Andres Andrea", "email": "anderson@imovies.ch",
    "pwd": ""
}
ssock.send(json.dumps(json_payload).encode())
print(ssock.recv(1024).decode())
ssock.close()
