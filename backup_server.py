# The server that will perform backups by receiving messages from the backup agent



import socket
import ssl
from threading import Thread
from threading import Lock
from os import listdir, remove, rename
from os.path import isfile, join, exists
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


#generate archive name (full path) from current time and the name of the backued up file
def getName(folder, name):

    now = datetime.now()

    return folder +"backup_"+ name +now.strftime("%d.%m.%Y%H:%M:%S")


#wrte in log that the backup failed
def log_failed_backup(e, ip):

    f = open(LOG_PATH, 'a')

    f.writelines("Backup failed for ip : "+ ip+" Error: "+str(e))

    f.close()
    return

#return True if the file is a known log file
def islog(filename):

    if("log" in filename):
        return True                 #TODO do better

    return False


# append changes from tpm to backup path
# remove tmp after
def append_changes(tmp_path, backup_path):

    if exists(backup_path): #if file exists append

        f = open(backup_path, 'r')
        lines = f.read().splitlines()

        last_line = lines[-1]

        f.close()

        b = open(backup_path, 'a+')

        bound = -1

        with open(tmp_path, 'r') as fp:

            for i, line in enumerate(fp):
                
                if(i > bound):
                    b.write(line)

                elif(line == last_line):
                    bound = i

        b.close()
    
    else:  #if file doesn't exist rename tmp file
        rename(tmp_path, backup_path)
        

    #delete tmp file if it exists
    if(exists(tmp_path)):
        remove(tmp_path)
                


#function that will communicate with the machines and perform the backups
def serve(conn, ip):

    print("demand from : "+ip)

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
        print("unrecognised client: "+ip)
        return

    #generate name for new backup

    modified_file_name = conn.recv(BUFFER_SIZE).decode()


    if islog(modified_file_name): #treat logs differently since we want to happend and not create a version for each new log line
        
        backup_path = backup_folder+"backup_"+modified_file_name

        tmp_path = backup_folder+"tmp"

        #write data in temp file
        
        lock.acquire()

        try:

            f = open(tmp_path, 'wb')

            data = conn.recv(BUFFER_SIZE)
                        
            while(data):
                f.write(data)
                data = conn.recv(BUFFER_SIZE)

            f.close()

        except Exception as e:
            print(e)
            print('error occured while performing backup')

            log_failed_backup(e, ip)
            conn.close()
            return

        finally:
            lock.release()

        #append changes at the end

        append_changes(tmp_path, backup_path)

    
    else: #normal backup

        backup_path = getName(backup_folder, modified_file_name)

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
            print('error occured while performing backup')

            log_failed_backup(e, ip)
            conn.close()
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
context.load_cert_chain('/home/backupp/backup_TLS_cert.pem', '/home/backupp/backup_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/backupp/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')
context.verify_mode = ssl.CERT_REQUIRED
context.post_handshake_auth = True

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

