#CA server that listens for incoming requests from the webserver
#The functions triggered match the system requirements as described in the "assignment" file
#CA ip : 10.10.10.3, webserver ip: 10.10.20.2



import socket
import ssl
from threading import Thread
from threading import Lock
from os import listdir
from os.path import isfile, join
from ca_core import *
from tools import *


#TLS Constants
WEBSERVER_IP= '10.10.20.2'
CA_IP = '10.10.10.3'
PORT = 6000
BUFFER_SIZE = 1024

#CA Constants

CERTIFICATES_PATH = "certificates/"
ISSUED_PATH = "certificates/issued/"
REVOKED_PATH = "certificates/revoked/"
ISSUED_HASH_PATH = CERTIFICATES_PATH + "hash/"
KEYS_PATH = "keys/"
ROOT_CERTIFICATE_PATH = CERTIFICATES_PATH + 'root_certificate.pem'
ROOT_PRIVATE_KEY_PATH = KEYS_PATH + "root_private_key.pem"
CA_DATA_PATH = "data/"
ISSUED_COUNTER = CA_DATA_PATH + "issued"
REVOKED_COUNTER = CA_DATA_PATH + "revoked"
SERIAL_NUMBER = CA_DATA_PATH + "serialnb"

#Protocol Constants

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

#Counters and synchronization
lock = Lock()


    
# returns the hash of all certificates
def get_all_hash_files(path):

    return [f for f in listdir(path) if (isfile(join(path, f)) and f.endswith('.hash'))]

def extract_id_from_hashname(hashname):

    buffer = ""

    for c in hashname:
        if c == '.':
            return buffer
        
        buffer += c
        
        if c == '/':
            buffer = ""

    return buffer

# Receive a certificate from the webserver
# compare it and returns the uid associated with the certificate
# or the "UNKNOWN_CERT" of "REVOKED_CERT" error message
def login_with_certificate(conn):

    crl = CRL()

    hash_digest = conn.recv(BUFFER_SIZE)

    certs_hash = get_all_hash_files(ISSUED_HASH_PATH)
    
    for cert in certs_hash :

        h = open(ISSUED_HASH_PATH + cert, 'rb').read(BUFFER_SIZE)

        if hash_digest == h:

            certificate = get_certificate_by_user_id(extract_id_from_hashname(cert))

            if is_revoked(certificate=certificate, crl_pem=crl.get_crl()[1]):  #certificate matching but revoked normally never goes here since hashes are deleted upon revokation

                conn.send(REVOKED_ERROR.encode())
                return

            else:   #found a matching certificate. send the corresponding uid

                uid = get_certificate_user_id(certificate)
                conn.send(uid.encode())
                return 

    #No matching certificate found
    conn.send(UNKNOWN_ERROR.encode())
    return

#Increase revoke counter using locks.
#counters are stored in the filesystem
def increase_revoke_counter():

    lock.acquire()
    try:
        f = open(REVOKED_COUNTER, 'r')
        counter = int(f.readline())
        f.close()

        f = open(REVOKED_COUNTER, 'w')
        f.writelines(str(counter+1))
        f.close()

    finally:
        lock.release()

#Increase issued counter using locks.
#counters are stored in the filesystem
def increase_issued_counter():

    lock.acquire()
    try:
        f = open(ISSUED_COUNTER, 'r')
        counter = int(f.readline())
        f.close()

        f = open(ISSUED_COUNTER, 'w')
        f.writelines(str(counter+1))
        f.close()

    finally:
        lock.release()

def get_issued_counter():

    f = open(ISSUED_COUNTER, 'r')
    counter = int(f.readline())
    f.close()

    return counter

def get_revoked_counter():

    f = open(REVOKED_COUNTER, 'r')
    counter = int(f.readline())
    f.close()

    return counter

def get_serial_number():

    f = open(SERIAL_NUMBER, 'r')
    number = int(f.readline())
    f.close()

    return number

#function that will communicate with the webserver and call the core CA functions
def serve(conn):

    #listen for requests
    request = conn.recv(BUFFER_SIZE)

    print('processing request')

    print(request.decode())

    if request.decode() == REVOKE_CERT:      #lauch revocation process

        uid = conn.recv(BUFFER_SIZE)
        
        try:
            certificate = get_certificate_by_user_id(uid.decode())
            
            crl = CRL()
            crl.update_crl(certificate)    #revoke certificate

            # remove hash of issued certificate
            os.remove(ISSUED_HASH_PATH+uid.decode()+'.hash')

            #increase revoke counter using lock
            increase_revoke_counter()

            #TODO send CRL to webserver since it must be published !

        except Exception as e:
            print(e.with_traceback())
            print("Failed to revoke certificate")
            conn.send(REVOKE_FAIL.encode())

        conn.send(REVOKE_OK.encode())


    elif request.decode() == NEW_CERT:       #launch creation of new certificate

        #listen for user informations (should be less than 1024 byte)
        uid = conn.recv(BUFFER_SIZE)

        #check that certificate not already issued.
        if get_certificate_by_user_id(uid.decode()) != None:
            conn.send(ALREADY_ISSUED_ERROR.encode())
            conn.close()
            return

        cert, _ = certificate_issuing(uid.decode())

        pkcs12 = create_pkcs12_bytes(ISSUED_PATH+get_certificate_name(cert), KEYS_PATH+uid.decode()+".pem")

        conn.send(pkcs12)
        
        #save hash
        digest = hash_bytes(pkcs12)

        f = open(ISSUED_HASH_PATH+uid.decode()+".hash",'wb')
        f.write(digest)
        f.close()

        #clean secret key
        os.remove(KEYS_PATH+uid.decode()+".pem")

        #increase the counter of issued certificates
        increase_issued_counter()

    elif request.decode() == STATS:

        #display stats about the CA

        stats = "ISSUED CERTS: "+str(get_issued_counter())+", REVOKED CERTS: "+str(get_revoked_counter())+", SERIAL NUMBER: "+str(get_serial_number())

        conn.send(stats.encode())

    elif request.decode() == LOGIN:

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
        




# Create root certificate and key if they don't exist
# and returns them
def getRootCertificatesAndKey():
    
    if os.path.exists(ROOT_CERTIFICATE_PATH) and os.path.exists(ROOT_PRIVATE_KEY_PATH):

        cert = read_certificate(ROOT_CERTIFICATE_PATH)
        key = load_key("root_private_key.pem")
        return cert, key

    else:
        return create_root_certificate('root_certificate.pem', "root_private_key.pem")


#check if all files countaining counters are present.
#if not they will be created
def check_counters_setup():

    lock.acquire()
    try:

        if not os.path.exists(ISSUED_COUNTER):
            f = open(ISSUED_COUNTER,'w')
            f.writelines("0")
            f.close()

        if not os.path.exists(REVOKED_COUNTER):
            f = open(REVOKED_COUNTER,'w')
            f.writelines("0")
            f.close()

        if not os.path.exists(SERIAL_NUMBER):
            f = open(SERIAL_NUMBER,'w')
            f.writelines("42069")
            f.close()
    finally:
        lock.release()

    return


####################Core CA Script######################


context = context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/coreca/CA_certificate.pem', '/home/coreca/CA_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/coreca/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) 

sock.bind((CA_IP, PORT))
sock.listen(5)              #TODO how many concurrent connnections are we expecting ? DDOS protections at the server or firewall level ?

ssock = context.wrap_socket(sock, server_side=True)


#Setup files if it is the first startup
getRootCertificatesAndKey()
check_counters_setup()

while True:

    # accept connections
    (conn, address) = ssock.accept()

    conn.settimeout(0.3)

    print('Connection received from '+str(address))

    if address[0] != WEBSERVER_IP:      #reject ip that are not the webserver
        conn.close()

    else:   #dispatch threads
                
        try:
            t = ClientThread(conn)
            t.start()
        except:
            print('Error when processing request')

