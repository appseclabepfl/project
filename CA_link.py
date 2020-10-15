#functions to communicate with the CA and trigger CA-related actions


import socket
import ssl
from tools import *

#operations supported by the CA

#operations supported by the server
REVOKE_CERT = 'REVOKE'
NEW_CERT = 'NEW'
STATS = 'STATS'
LOGIN = 'LOGIN'

#messages sent by server
REVOKE_OK = 'revocationOK'
REVOKE_FAIL = 'revocationFAIL'
REVOKED_ERROR = 'REVOKED_CERT'
UNKNOWN_ERROR = 'UNKNOWN_CERT'
ALREADY_ISSUED_ERROR = 'ALREADY_ISSUED'

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/webserver/webserver_certificate.pem', '/home/webserver/webserver_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/webserver/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')
    
CA_IP = '10.10.10.3'
CA_PORT = 6000

BUFFER_SIZE = 1024




#function to ask for a new certificate
#return -1 in case of error, 0 otherwise
def getNewCert(savePath, userInfo):   #TODO what information should we give to the CA to generate certs ? email name surname etc...
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
            ssock.settimeout(0.3)

            try:
                ssock.connect((CA_IP, CA_PORT))

                #send instruction
                ssock.send(NEW_CERT.encode())

                #send user info to CA
                ssock.send(userInfo.encode())
               
                data = ssock.recv(BUFFER_SIZE)  
                
                if(data.decode() == ALREADY_ISSUED_ERROR):   #check for error message, launches error if it is not an error message
                    ssock.close()
                    print('Certificate already issued for this user')
                    return -1


            except UnicodeError:        #it means that it is the content of the PKCSfile and not an error message

                #save certificate
                f = open(savePath, 'wb')    
                
                while(data):
                    f.write(data)
                    data = ssock.recv(BUFFER_SIZE)
                
                f.close()

                ssock.close()


            except Exception as e:
                print(e)
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
                ssock.connect((CA_IP, CA_PORT))

                #send instruction
                ssock.send(REVOKE_CERT.encode())

                ssock.send(userInfo.encode())                     

                status = ssock.recv(BUFFER_SIZE)

                if status.decode() != REVOKE_OK:         #TODO retrieve CRL from core CA and publish it
                    ssock.close()
                    return -1

                ssock.close()

            except Exception as e:
                print(e)
                print('error occured while revoking the certificate')
                ssock.close()
                return -1

    return 0

#Function that admin can use to receive the CA's stats
#returns a string containing the stats or an empty string
#DANGER: should only be called after a CA ADMIN login using its CERTIFICATE
def getCAStats():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:

            ssock.settimeout(0.3)

            CA_stats = ''

            try:
                ssock.connect((CA_IP, CA_PORT))

                #send instruction                             
                ssock.send(STATS.encode())

                data = ssock.recv(BUFFER_SIZE)
                
                while(data):
                    CA_stats += data.decode()
                    data = ssock.recv(BUFFER_SIZE)

                ssock.close()
                    
                return CA_stats

            except Exception as e:
                print(e)
                print('error while getting CA stats')
                ssock.close()
                return CA_stats


#Function used to log in using the certificate
#returns the user id corresponding to the certificate or None in case of failure
def login_with_certificate(cert_path):
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
        
            try:
                ssock.connect((CA_IP, CA_PORT))

                #trigger login procedure
                ssock.send(LOGIN.encode())

                #compute hash of certificate
                digest = hash_file(cert_path)

                ssock.send(digest)
                uid = ssock.recv(BUFFER_SIZE)

                if (uid.decode() == REVOKED_ERROR):       #check for error messages
                    ssock.close()
                    print('Certificate was revoked for this user')
                    return ""

                if(uid.decode() == UNKNOWN_ERROR):
                    ssock.close()
                    print('Unknown certificate submitted')
                    return ""

                ssock.close()
                return uid.decode()

            except Exception as e:
                print(e)
                print('Error during login procedure using certificate')
                ssock.close()
                return ""