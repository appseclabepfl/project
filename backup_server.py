# The server that will perform backups by receiving messages from the backup agent



import socket
import ssl
from threading import Thread
from threading import Lock
from os import listdir
from os.path import isfile, join
from datetime import datetime

#LOCAL PATHS

LOG_PATH = '/home/backupp/logs'

#TLS Constants
WEBSERVER_IP= '10.10.20.2'
CA_IP = '10.10.10.3'
BACKUP_IP = '10.10.10.4'
DB_IP = '10.10.10.2'
FIREWALL_IP = '10.10.10.1'
PORT = 5555
BUFFER_SIZE = 1024


#Protocol Constants
CA_BACKUP_PATH = ''
DB_BACKUP_PATH = ''
FIREWALL_BACKUP_PATH = ''
WEBSERVER_BACKUP_PATH = ''

#Counters and synchronization
lock = Lock()


#generate archive name (full path) fro current time
def getName(folder):

    now = datetime.now()

    return folder + now.strftime("%d/%m/%Y %H:%M:%S")


#wrte in log that the backup failed
def notify_failed_backup(e, ip):

    f = open(LOG_PATH, 'a+')

    f.writelines("Backup failed for ip : "+ ip+" Error: "+str(e))

    f.close()
    return



#function that will communicate with the machines and perform the backups
def serve(conn, ip):

    backup_folder = ""

    if(ip == CA_IP):
        backup_folder = CA_BACKUP_PATH

    elif(ip == WEBSERVER_IP):
        backup_folder = WEBSERVER_BACKUP_PATH

    elif(ip == FIREWALL_IP):
        backup_folder = FIREWALL_BACKUP_PATH

    elif(ip == DB_IP):
        backup_folder = DB_BACKUP_PATH


    else:
        conn.close()
        return

    #generate name for new backup

    backup_path = getName(backup_folder)

    #perform backup

    lock.acquire()

    try:

        f = open(backup_path, 'wb')

        data = conn.recv(BUFFER_SIZE)
                    
        while(data):
            f.write(data)
            data = conn.recv(BUFFER_SIZE)

        f.close()

    except Exception as e:
                print(e)
                print('error occured while performaing backup')
                notify_failed_backup(e, ip)
                return

    finally:
        lock.release()

    conn.close()
    return



class ClientThread(Thread):

    def __init__(self,connection, ip):
        Thread.__init__(self)
        self.conn = connection
        self.ip_addr = ip
        
    def run(self):
        serve(self.conn, self.ip_addr)
        return
        




####################Backup Server######################


context = context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/backupp/backup_certificate.pem', '/home/backupp/backup_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/backupp/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) 

sock.bind((BACKUP_IP, PORT))
sock.listen(5)              

ssock = context.wrap_socket(sock, server_side=True)


while True:

    # accept connections
    (conn, address) = ssock.accept()

    conn.settimeout(0.3)

    print('Connection received from '+str(address))

    #dispatch threads
                
    try:
        t = ClientThread(conn, address[0])
        t.start()
    except:
        print('Error when processing request')

