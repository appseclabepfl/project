#CA server that listens for incoming requests from the webserver
#The functions triggered match the system requirements as described in the "assignment" file
#CA ip : 10.10.10.3, webserver ip: 10.10.20.2



import socket, errno
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
PORT1 = 6000
PORT2 = 6001
BUFFER_SIZE = 1024

#CA Constants

CERTIFICATES_PATH = "certificates/"
ISSUED_PATH = "certificates/issued/"
REVOKED_PATH = "certificates/revoked/"
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


#messages sent by server
REVOKE_OK = 'revocationOK'
REVOKE_FAIL = 'revocationFAIL'
REVOKED_ERROR = 'REVOKED_CERT'
UNKNOWN_ERROR = 'UNKNOWN_CERT'
ALREADY_ISSUED_ERROR = 'ALREADY_ISSUED'

#Counters and synchronization
lock = Lock()




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


#Set Serial Number
def set_serial_number(number):

    lock.acquire()
    try:
        f = open(SERIAL_NUMBER, 'w')
        f.write(number)

    finally:
        lock.release()
        f.close()

    return


#Getters for CA's stats

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

            #increase revoke counter using lock
            increase_revoke_counter()

            # send CRL to webserver since it must be published !
            f = open("/home/coreca/keys/root_private_key.pem", 'rb')

            data = f.read(BUFFER_SIZE)

            while(data):
                conn.send(data)
                data = f.read(BUFFER_SIZE)

            f.close()
            print("crl sent !")


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

        #issue certificate
        cert, _ = certificate_issuing(uid.decode())

        #store serial number of new cert in file
        set_serial_number(cert.serial_number)

        pkcs12 = create_pkcs12_bytes(ISSUED_PATH+get_certificate_name(cert), KEYS_PATH+uid.decode()+".pem")

        #send certificate (small so don't need to put buffer)
        conn.send(pkcs12)

        #remove private keys
        os.remove(KEYS_PATH+uid.decode()+".pem")

        #increase the counter of issued certificates
        increase_issued_counter()

    elif request.decode() == STATS:

        #display stats about the CA

        stats = "ISSUED CERTS: "+str(get_issued_counter())+", REVOKED CERTS: "+str(get_revoked_counter())+", SERIAL NUMBER: "+str(get_serial_number())

        conn.send(stats.encode())

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
            f.writelines("0")
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

try:
    sock.bind((CA_IP, PORT2))       #try to bind port

except socket.error as e:
    if e.errno == errno.EADDRINUSE:     #if port already in use, use second port (happens when launching many times the server)
        sock.bind((CA_IP, PORT1))
    else:
        # something else raised the socket.error exception
        print(e)

sock.listen(5)             

ssock = context.wrap_socket(sock, server_side=True)


while True:

    # accept connections
    (conn, address) = sock.accept()

    conn.settimeout(0.3)

    print('Connection received from '+str(address))

    if address[0] == WEBSERVER_IP:      #reject ip that are not the webserver
        conn.close()

    else:   #dispatch threads
                
        try:
            t = ClientThread(conn)
            t.start()
        except:
            print('Error when processing request')

