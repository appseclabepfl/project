#functions to communicate with the CA and trigger CA-related actions


import socket
import ssl
from tools import *

#operations supported by the CA

revoke_cert = 'REVOKE'
new_cert = 'NEW'
stats = 'STATS'

#messages sent by teh CA

revoke_OK = 'revocationOK'
revoke_FAIL = 'revocationFAIL'

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.load_verify_locations('/home/webserver/rootCA.pem')      #path to certificate for TLS 
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.set_ciphers('ECDHE-RSA-AES256-SHA384')
    
CA_IP = '10.10.10.3'
CA_port = 6000

BUFFER_SIZE = 1024

#Send shared key to CA server to authenticate the request
#Prevent spoofing attacks
def sendKey(conn):

    f = open('/home/webserver/shared_key.txt', 'rb')

    key = f.read(BUFFER_SIZE)

    conn.send(key)

    return



#function to ask for a new certificate
#return -1 in case of error, 0 otherwise
def getNewCert(savePath, userInfo):   #TODO what information should we give to the CA to generate certs ? email name surname etc...
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
            ssock.settimeout(0.3)

            try:
                ssock.connect((CA_IP, CA_port))

                #send authentification key
                sendKey(ssock)

                #send instruction
                ssock.send(new_cert.encode())

                #send user info to CA
                ssock.send(userInfo.encode())

                #retrieve certificate
                f = open(savePath, 'wb')
               
                data = ssock.recv(BUFFER_SIZE)               
                
                while(data):
                    f.write(data)
                    data = ssock.recv(BUFFER_SIZE)

                f.close()

                ssock.close()

            except:
                print('error occured while creating new certificate')
                ssock.close()
                return -1

    return 0


#function to revoke a certificate of a specific user
#return -1 in case off error, 0 otherwise
def revokeCert(userInfo):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
            ssock.settimeout(0.3)

            try:
                ssock.connect((CA_IP, CA_port))

                #send authentification key
                sendKey(ssock)

                #send instruction
                ssock.send(revoke_cert.encode())

                ssock.send(userInfo.encode())                     

                status = ssock.recv(BUFFER_SIZE)

                if status != revoke_OK:
                    ssock.close()
                    return -1

                ssock.close()

            except:
                print('error occured while revoking the certificate')
                ssock.close()
                return -1

    return 0

#Function that admin can use to receive the CA's stats
#return a string containing the stats or an empty string
def getCAStats():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:

            ssock.settimeout(0.3)

            CA_stats = ''

            try:
                ssock.connect((CA_IP, CA_port))

                #send authentification key
                sendKey(ssock)

                #send instruction                             
                ssock.send(stats.encode())

                data = ssock.recv(BUFFER_SIZE)
                
                while(data):
                    CA_stats += data.decode()
                    data = ssock.recv(BUFFER_SIZE)

                ssock.close()
                    
                return CA_stats

            except:
                print('error while getting CA stats')
                ssock.close()
                return CA_stats


#Function used to log in using the certificate
#returns the user id corresponding to the certificate or None in case of failure
def login_with_certificate(cert_path):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
        
            try:
                #compute hash of certificate
                digest = hash_file(cert_path)

                ssock.send(digest)
                uid = ssock.recv(BUFFER_SIZE)

                return uid.decode()
            except:
                print('Error during login procedure using certificate')
                return None