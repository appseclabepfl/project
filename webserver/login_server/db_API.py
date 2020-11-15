import socket
import base64
import json
import ssl

DB_IP = '10.10.10.2'
DB_PORT = 42069
BUFFER_SIZE = 1024

CHECK_PASSWORD = "CHECK_PASSWORD"
GET_USER_DATA = "GET_USER_DATA"
UPDATE_USER_DATA = "UPDATE_USER_DATA"

def init():
	context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
	context.verify_mode = ssl.CERT_REQUIRED
	context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
	context.load_cert_chain('cert/webserver_certificate.pem', 'cert/webserver_TLS_pk.key')
	context.load_verify_locations('cert/rootCA.pem')
	context.set_ciphers('ECDHE-RSA-AES256-SHA384')
	return context

def get_new_socket_for(query, context):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ssock = context.wrap_socket(sock)
	ssock.connect((DB_IP, DB_PORT))
	ssock.send(query.encode())
	print("Answer to prepare", ssock.recv(BUFFER_SIZE).decode())
	return ssock

def check_password(uid, pwd, context):
	ssock = get_new_socket_for(CHECK_PASSWORD, context)
	ssock.send(base64.b64encode(uid+":"+pwd).encode())
	sucess = ssock.recv(BUFFER_SIZE).decode()
	ssock.close()
	return sucess == 1

def get_user_data(uid, context):
	ssock = get_new_socket_for(GET_USER_DATA, context)
	ssock.send(base64.b64encode(uid).encode())
	data = json.loads(ssock.recv(BUFFER_SIZE))
	ssock.close()
	if data.get("error_msg") is not None: #If non-existent user
		return None
	return data

def update_user_data(data, context):
	ssock = get_new_socket_for(UPDATE_USER_DATA, context)
	ssock.send(json.dumps(data).encode())
	print("Response to update", ssock.recv(BUFFER_SIZE).decode())
	ssock.close()
	return

