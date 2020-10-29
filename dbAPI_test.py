import socket
import base64
import hashlib
import json

DB_IP = '192.168.56.101'
port = 42069
CHECK_PASSWORD = 'CHECK_PASSWORD'
GET_USER_DATA = 'GET_USER_DATA'
UPDATE_USER_DATA = 'UPDATE_USER_DATA'
username = 'a3'
pwd_clear = 'Astrid'

## CHECK PASSWORD TEST
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((DB_IP, port))
sock.send(CHECK_PASSWORD.encode())
print(sock.recv(1024).decode())
hashed = hashlib.sha1(pwd_clear).hexdigest()
sock.send(base64.b64encode(username+":"+hashed).encode())
print(sock.recv(1024).decode())
sock.close()
print("#######################################################")
## GET USER DATA TEST EXISTING USER
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((DB_IP, port))
sock.send(GET_USER_DATA.encode())
print(sock.recv(1024).decode())
sock.send(base64.b64encode(username).encode())
response = json.loads(sock.recv(1024))
print(response["uid"])
print(response["lastname"])
print(response["firstname"])
print(response["email"])
print(response["response_code"])
print(response["error_msg"])
sock.close()
print("#######################################################")
## GET USER DATA TEST NON EXISTING USER
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((DB_IP, port))
sock.send(GET_USER_DATA.encode())
print(sock.recv(1024).decode())
sock.send(base64.b64encode("dummy").encode())
response = json.loads(sock.recv(1024))
print(response["response_code"])
print(response["error_msg"])
sock.close()
print("#######################################################")
## UPDATE EMAIL ADDRESS AND ROLLBACK
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((DB_IP, port))
sock.send(UPDATE_USER_DATA.encode())
print(sock.recv(1024).decode())
json_payload = {
    "uid": "a3", "lastname": "Anderson",
    "firstname": "Andres Andrea", "email": "updated@email.ch",
    "pwd": ""
}
sock.send(json.dumps(json_payload).encode())
print(sock.recv(1024).decode())
sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((DB_IP, port))
sock.send(GET_USER_DATA.encode())
print(sock.recv(1024).decode())
sock.send(base64.b64encode(username).encode())
response = json.loads(sock.recv(1024))
print(response["uid"])
print(response["lastname"])
print(response["firstname"])
print(response["email"])
print(response["response_code"])
print(response["error_msg"])
sock.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((DB_IP, port))
sock.send(UPDATE_USER_DATA.encode())
print(sock.recv(1024).decode())
json_payload = {
    "uid": "a3", "lastname": "Anderson",
    "firstname": "Andres Andrea", "email": "anderson@imovies.ch",
    "pwd": ""
}
sock.send(json.dumps(json_payload).encode())
print(sock.recv(1024).decode())
sock.close()
