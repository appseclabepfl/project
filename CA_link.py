#functions to communicate with the CA and trigger CA-related actions


import socket
import ssl


#operations supported by the CA

#operations supported by the server
REVOKE_CERT = 'REVOKE'
NEW_CERT = 'NEW'
STATS = 'STATS'
CONTINUE= 'CONT'
VERIFY = 'VERIFY'


#messages sent by server
ALREADY_ISSUED_ERROR = 'ALREADY_ISSUED'

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/webserver/webserver_certificate.pem', '/home/webserver/webserver_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/webserver/rootCA.crt')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')
context.verify_mode = ssl.CERT_REQUIRED

    
CA_IP = '10.10.10.3'
CA_PORT1 = 6000
CA_PORT2 = 6000

BUFFER_SIZE = 1024

#PATHS

CRL_PATH = "/home/webserver/crl.pem"




#function to ask for a new certificate
#return -1 in case of error, 0 otherwise
def getNewCert(savePath, userInfo):   #TODO what information should we give to the CA to generate certs ? email name surname etc...
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
            ssock.settimeout(0.3)

            try:
                ssock.connect((CA_IP, CA_PORT1))
            except:
                ssock.connect((CA_IP, CA_PORT2))
            
            try:

                #send instruction
                ssock.send(NEW_CERT.encode())

                status = ssock.recv(BUFFER_SIZE)

                if(status.decode() != CONTINUE):
                    ssock.shutdown(socket.SHUT_RDWR)   
                    ssock.close()
                    return -1

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
                ssock.connect((CA_IP, CA_PORT1))
            except:
                ssock.connect((CA_IP, CA_PORT2))
            
            try:

                #send instruction
                ssock.send(REVOKE_CERT.encode())

                status = ssock.recv(BUFFER_SIZE)

                if(status.decode() != CONTINUE):
                    ssock.shutdown(socket.SHUT_RDWR)   
                    ssock.close()
                    return -1

                #send user informations (uid)
                ssock.send(userInfo.encode())                     

                # retrieve CRL from core CA 

                f = open(CRL_PATH, 'wb')
                data = ssock.recv(BUFFER_SIZE)

                while(data):
                    f.write(data)
                    data = ssock.recv(BUFFER_SIZE)

                f.close()


                ssock.shutdown(socket.SHUT_RDWR)
                ssock.close()

            except Exception as e:
                print(e)
                print('error occured while revoking the certificate')
                
                ssock.shutdown(socket.SHUT_RDWR)
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
                ssock.connect((CA_IP, CA_PORT1))
            except:
                ssock.connect((CA_IP, CA_PORT2))
            
            try:

                #send instruction                             
                ssock.send(STATS.encode())

                data = ssock.recv(BUFFER_SIZE)
                
                while(data):
                    CA_stats += data.decode()
                    data = ssock.recv(BUFFER_SIZE)

                ssock.shutdown(socket.SHUT_RDWR)
                ssock.close()
                    
                return CA_stats

            except Exception as e:
                print(e)
                print('error while getting CA stats')
                ssock.shutdown(socket.SHUT_RDWR)
                ssock.close()
                return CA_stats



#Function to check if a certificate is valid
#takes fullpath to certificate as argument
#returns true or false
def verify_certificate(cert_bytes):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:

            ssock.settimeout(0.3)

            try:
                ssock.connect((CA_IP, CA_PORT1))
            except:
                ssock.connect((CA_IP, CA_PORT2))
            
            try:

                #send instruction                             
                ssock.send(VERIFY.encode())

                status = ssock.recv(BUFFER_SIZE)

                if status.decode() == CONTINUE:

                    #send certificate

                    f = open(cert_path, 'rb')

                    ssock.send(cert_bytes)
                    
                    #retrieve answer

                    res = ssock.read(BUFFER_SIZE)

                    ssock.shutdown(socket.SHUT_RDWR)
                    ssock.close()

                    return res.decode() == "False"
                        
                    
            except Exception as e:
                print(e)
                print('error while getting CA stats')

            finally:
                ssock.shutdown(socket.SHUT_RDWR)
                ssock.close()

            return False
