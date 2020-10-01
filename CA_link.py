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



BUFFER_SIZE = 1024

#function that connect to the CA using TLS and returns the connected socket
def connectToCA():

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations('../keys_and_certs/rootCA.pem')       
    
    CA_IP = '10.10.10.3'
    CA_port = 5000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

        with context.wrap_socket(sock) as ssock:

            ssock.connect(CA_IP, CA_port)
            
            return ssock


#function to ask for a new certificate
def getNewCert(savePath, userInfo):   #TODO what information should we give to the CA to generate certs ? email name surname etc...

    conn = connectToCA()
    conn.sendall(new_cert)

    #send user info to CA

    conn.sendall(userInfo)

    #retrieve certificate

    f = open(savePath, 'wb')

    data = conn.recv(BUFFER_SIZE)               #TODO put timouts if no answer ?

    while(data):
        f.write(data)
        data = conn.recv(BUFFER_SIZE)

    f.close()

    conn.close()

    return 0


def revokeCert(userInfo):

    conn = connectToCA()

    conn.sendall(revoke_cert)

    conn.sendall(userInfo)                      #TODO put timouts if no answer ?

    status = conn.recv(BUFFER_SIZE)

    if status != revoke_OK:
        conn.close()
        return -1

    conn.close()
    return 0


def getCAStats():

    conn = connectToCA()                        #TODO put timouts if no answer ?
    conn.sendall(stats)

    CA_stats = ''

    data = conn.recv(BUFFER_SIZE)

    while(data):
        CA_stats += data
        data = conn.recv(BUFFER_SIZE)

    conn.close()
    
    return data