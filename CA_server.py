#CA server that listens for incoming requests from the webserver
#The functions triggered match the system requirements as described in the "assignment" file
#CA ip : 10.10.10.3, webserver ip: 10.20.20.2



import socket
import ssl
from threading import Thread
from os import listdir
from os.path import isfile, join
from ca_core import *
from tools import *


#TLS Constants
webserver_IP= '10.10.20.2'
CA_IP = '10.10.10.3'
port = 6000
BUFFER_SIZE = 1024

#CA Constants

CERTIFICATES_PATH = "certificates/"
ISSUED_PATH = "certificates/issued/"
REVOKED_PATH = "certificates/revoked/"
KEYS_PATH = "keys/"
ROOT_CERTIFICATE_PATH = CERTIFICATES_PATH + 'root_certificate.pem'
ROOT_PRIVATE_KEY_PATH = KEYS_PATH + "root_private_key.pem"

#Protocol Constants

#operations supported by the server
revoke_cert = 'REVOKE'
new_cert = 'NEW'
stats = 'STATS'
login = 'LOGIN'

#messages sent by server
revoke_OK = 'revocationOK'
revoke_FAIL = 'revocationFAIL'
REVOKED_ERROR = 'REVOKED_CERT'
UNKNOWN_ERROR = 'UNKNOWN_CERT'


#Check that the client knows the shared key. 
#Prevent spoofing attacks from the client's side in case the firewall doesn't work
def checkKey(conn):

    key = conn.recv(BUFFER_SIZE)

    f = open('/home/coreca/shared_key.txt','rb')

    real_key = f.read(BUFFER_SIZE)

    if key == real_key:
        f.close()
        print("webserver correctly authenticated")
        return True

    f.close()
    return False
    
# returns the names of all certificates in folder
def get_all_certificates(path):

    return [f for f in listdir(path) if (isfile(join(path, f)) and f.endswith('.pem'))]


# Receive a certificate from the webserver
# compare it and returns the uid associated with the certificate
# or the "UNKNOWN_CERT" of "REVOKED_CERT" error message
def login_with_certificate(conn):

    crl = CRL() #TODO check that it remembers already revoked certs

    hash_digest = conn.recv(BUFFER_SIZE)

    certs = get_all_certificates(ISSUED_PATH)
    # TODO: check format of certificates names
    for c in certs :
        h = hash_file(c)

        if hash_digest == h:

            cert = read_certificate(c)

            if is_revoked(cert, crl=crl):  #certificate matching but revoked

                conn.send(REVOKED_ERROR.encode())

            else:   #found a matching certificate. send the correpsonding uid

                uid = get_certificate_user_id(cert)
                conn.send(uid.encode())
                return 

    #No matching certificate found
    conn.send(UNKNOWN_ERROR.encode())
    return


#function that will communicate with the webserver and call the core CA functions
def serve(conn):


    #check key (prevent spoofing attacks)
    if not checkKey(conn):
        print("Unauthorized access: bad key")
        conn.close()
        return

    #listen for requests
    request = conn.recv(BUFFER_SIZE)

    print('processing request')

    print(request.decode())

    if request.decode() == revoke_cert:      #lauch revocation process

        uid = conn.recv(BUFFER_SIZE)
        
        try:
            # TODO get certificate using uid
            cert = get_certificate_by_user_id(uid.decode())
            
            crl = CRL()
            crl.update_crl(cert)
        
        except:
            conn.send(revoke_FAIL.encode())

        conn.send(revoke_OK.encode())


    elif request.decode() == new_cert:       #launch creation of new certificate

        #listen for user informations (should be less than 1024 byte)

        uid = conn.recv(BUFFER_SIZE)

        cert, private_key = certificate_issuing(uid.decode())

        #send the certificate and the key #TODO format OK with requirements ????

        cert_path = get_certificate_name(cert)
        key_path = #TODO 2 in one format or separate ?????
        f = open(cert_path, 'rb')

        data = f.read(BUFFER_SIZE)
        print(data.decode())
        while(data):         
            conn.send(data)
            data = f.read(BUFFER_SIZE)

        f.close()
        


    elif request.decode() == stats:

        #display stats about the CA

        #TODO send back the stats
        stats = 'CA stats....'

        conn.send(stats.encode())

    elif request.decode() == login:

        #check if there is a matching certificate and send back uid to webserver
        login_with_certificate(conn)

    else:

        print("Invalid instruction")

    conn.close()

    return



class ClientThread(Thread):

    def __init__(self,connection):
        Thread.__init__(self)
        self.conn = connection
        
    def run(self):
        serve(self.conn)
        return
        




# Retrieve root certificate and root key if they exist
# Create them otherwise
def getRootCertificatesAndKey():
    
    if os.path.exists(ROOT_CERTIFICATE_PATH) and os.path.exists(ROOT_PRIVATE_KEY_PATH):

        cert = read_certificate(ROOT_CERTIFICATE_PATH)
        key = load_key("root_private_key.pem")
        return cert, key

    else:
        return create_root_certificate('root_certificate.pem', "root_private_key.pem")






context = context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/coreca/CA_certificate.pem', '/home/coreca/CA_TLS_pk.key')       #Path to certificates for TLS comunication
context.set_ciphers('ECDHE-RSA-AES256-SHA384')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) 

sock.bind((CA_IP, port))
sock.listen(5)              #TODO how many concurrent connnections are we expecting ? DDOS protections at the server or firewall level ?

ssock = context.wrap_socket(sock, server_side=True)


while True:

    # accept connections
    (conn, address) = ssock.accept()

    conn.settimeout(0.3)

    print('Connection received from '+str(address))

    if address[0] != webserver_IP:      #reject ip that are not the webserver
        conn.close()

    else:   #dispatch threads
                
        try:
            t = ClientThread(conn)
            t.start()
        except:
            print('Error when processing request')

