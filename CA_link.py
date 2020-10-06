#functions to communicate with the CA and trigger CA-related actions


import socket
import ssl


#operations supported by the CA

revoke_cert = 'REVOKE'
new_cert = 'NEW'
stats = 'STATS'

#messages sent by teh CA

revoke_OK = 'revocationOK'
revoke_FAIL = 'revocationFAIL'

context = ssl.SSLContext(ssl.PROTOCOL_TLS, ssl.OP_NO_SSLv3)

context.load_verify_locations('/home/webserver/rootCA.pem')       
    
CA_IP = '10.10.10.3'
CA_port = 6000

BUFFER_SIZE = 1024



#function to ask for a new certificate
def getNewCert(savePath, userInfo):   #TODO what information should we give to the CA to generate certs ? email name surname etc...
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
            ssock.settimeout(0.3)

            try:
                ssock.connect((CA_IP, CA_port))

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


def revokeCert(userInfo):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:
            ssock.settimeout(0.3)

            try:
                ssock.connect((CA_IP, CA_port))

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


def getCAStats():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock, server_hostname=CA_IP) as ssock:

            ssock.settimeout(1)

            CA_stats = ''

            try:
                ssock.connect((CA_IP, CA_port))
                                                
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