#CA server that listens for incoming requests from the webserver
#The functions triggered match the system requirements as described in the "assignment" file
#CA ip : 10.10.10.3, webserver ip: 10.10.20.2



import socket, errno
import ssl
import time
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

HOME = "/home/coreca/"
LOG_PATH = HOME+"CA_server_logs"

#CA Constants

CERTIFICATES_PATH = HOME+"certificates/"
ISSUED_PATH = HOME+"certificates/issued/"
REVOKED_PATH = HOME+"certificates/revoked/"
KEYS_PATH = HOME+"keys/"
ROOT_CERTIFICATE_PATH = CERTIFICATES_PATH + 'root_certificate.pem'
ROOT_PRIVATE_KEY_PATH = KEYS_PATH + "root_private_key.pem"
CA_DATA_PATH = HOME+"data/"
ISSUED_COUNTER = CA_DATA_PATH + "issued"
REVOKED_COUNTER = CA_DATA_PATH + "revoked"
SERIAL_NUMBER = CA_DATA_PATH + "serialnb"

#Protocol Constants

#operations supported by the server
REVOKE_CERT = 'REVOKE'
NEW_CERT = 'NEW'
STATS = 'STATS'
VERIFY = 'VERIFY'
CONTINUE = 'CONT'


#messages sent by server
ALREADY_ISSUED_ERROR = 'ALREADY_ISSUED'

#Counters and synchronization
lock = Lock()

# Returns actual time and date
def get_timestamp():
    now = datetime.datetime.now()
    return now.strftime("%d.%m.%Y%H:%M:%S")


#wrte in log that the backup failed
def log_event(event):

    f = open(LOG_PATH, 'a')

    f.writelines(event+", time and date : "+get_timestamp())

    f.close()
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


#Set Serial Number
def set_serial_number(number):

    lock.acquire()
    try:
        f = open(SERIAL_NUMBER, 'w')
        f.write(str(number))

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
    number = f.read(BUFFER_SIZE)
    if(number.isnumeric()):
        f.close()
        return number

    return -1

#remove private key from
def remove_key(filename):

    try:
        lock.acquire()
        os.remove(KEYS_PATH+filename)
    finally:
        lock.release()

    return


#function that will communicate with the webserver and call the core CA functions
def serve(conn):

    #listen for requests
    request = conn.recv(BUFFER_SIZE)

    log_event('processing request')

    log_event(request.decode())

    if request.decode() == REVOKE_CERT:      #lauch revocation process

        conn.send(CONTINUE.encode())

        uid = conn.recv(BUFFER_SIZE)
        
        try:
            certificate = get_certificate_by_user_id(uid.decode())
            if(certificate != None):
                crl = CRL()
                crl.update_crl(certificate)    #revoke certificate

                #increase revoke counter using lock
                increase_revoke_counter()

            # send CRL to webserver since it must be published !
            f = open(CERTIFICATES_PATH + "crl.pem", 'rb')

            data = f.read(BUFFER_SIZE)

            while(data):
                conn.send(data)
                data = f.read(BUFFER_SIZE)

            f.close()
            log_event("crl sent !")


        except Exception as e:
            print(e.with_traceback())
            log_event("Failed to revoke certificate")


    elif request.decode() == NEW_CERT:       #launch creation of new certificate

        conn.send(CONTINUE.encode())

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

        pkcs12 = create_pkcs12_bytes(ISSUED_PATH+get_certificate_name(cert), KEYS_PATH+uid.decode()+"private_key"+".pem")

        #send certificate (small so don't need to put buffer)
        conn.send(pkcs12)

        #remove private keys
        t = DelayedRemoveThread(10, uid.decode()+"private_key"+".pem")
        t.start()

        #increase the counter of issued certificates
        increase_issued_counter()

    elif request.decode() == STATS:

        #display stats about the CA

        stats = "ISSUED CERTS: "+str(get_issued_counter())+", REVOKED CERTS: "+str(get_revoked_counter())+", SERIAL NUMBER: "+str(get_serial_number())

        conn.send(stats.encode())

    elif request.decode() == VERIFY:

        conn.send(CONTINUE.encode())

        #retrieve certificate

        try:
            f = open(HOME+"tmp_cert_verification", 'wb')

            data = conn.recv(BUFFER_SIZE)

            while(data):
                try:
                    if CONTINUE in data.decode():
                        f.write(data[:len(data) -8])
                        break
                except:
                    f.write(data)
                    data = conn.recv(BUFFER_SIZE)

            f.close()


        #verify vertificate and return result

            root_key = serialization.load_pem_private_key(open(KEYS_PATH+"root_private_key.pem", 'rb').read(), None, backend=default_backend())
            cert = x509.load_pem_x509_certificate(open(HOME+"tmp_cert_verification", 'rb').read(), default_backend())

            result = verify_certificate(cert, root_key)

            if result:
                conn.send("True".encode())
            else:
                conn.send("False".encode())


        except Exception as e:
            print(e.with_traceback())
            log_event("Failed to verify certificate")


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
        
class DelayedRemoveThread(Thread):

    def __init__(self,time, path):
        Thread.__init__(self)
        self.time = time
        self.remove_path = path
        
    def run(self):
        time.sleep(self.time)
        remove_key(self.remove_path)
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
context.load_cert_chain(certfile='/home/coreca/CA_certificate.crt', keyfile='/home/coreca/CA_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/coreca/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')
context.verify_mode = ssl.CERT_REQUIRED
context.post_handshake_auth = True


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) 

try:
    sock.bind((CA_IP, PORT1))       #try to bind port

except socket.error as e:
    if e.errno == errno.EADDRINUSE:     #if port already in use, use second port (happens when launching many times the server)
        sock.bind((CA_IP, PORT2))
    else:
        # something else raised the socket.error exception
        print(e)


sock.listen(5)             

ssock = context.wrap_socket(sock, server_side=True)


#Setup files if it is the first startup
getRootCertificatesAndKey()
check_counters_setup()

while True:

    # accept connections
    (conn, address) = ssock.accept()

    conn.settimeout(0.3)

    log_event('Connection received from '+str(address)+", time and date : "+get_timestamp())

    if address[0] != WEBSERVER_IP:      #reject ip that are not the webserver
        conn.close()

    else:   #dispatch threads
                
        try:
            t = ClientThread(conn)
            t.start()
        except:
            log_event('Error when processing request')

