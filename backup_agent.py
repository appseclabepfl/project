#script that will monitor folders and files and perform backup upon change


import socket
import ssl
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from os import remove
from os.path import basename
from tools import *


#SSL connection

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/coreca/CA_certificate.pem', '/home/coreca/CA_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/coreca/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')
    
BACKUP_IP = '10.10.10.4'
BACKUP_PORT = 5555

BUFFER_SIZE = 1024

#Paths
HOME_DIR = '/home/coreca/'

#Path to watch
CERTS = HOME_DIR+"certificates"


#Private Key Path
backup_key_path = '/home/coreca/backup_key'


#Watchers and Event Handlers 
#(see: https://www.michaelcho.me/article/using-pythons-watchdog-to-monitor-changes-to-a-directory)

class Handler(FileSystemEventHandler):

    @staticmethod
    def on_any_event(event):

        if event.is_directory:
            return None

        elif event.event_type == 'created':
            # Take any action here when a file is first created.
            launch_backup(basename(event.src_path), event.src_path)

        elif event.event_type == 'modified':
            # Taken any action here when a file is modified.
            launch_backup(basename(event.src_path), event.src_path)

        elif event.event_type == 'moved':
            # Taken any action here when a file is moved.
            launch_backup(basename(event.src_path), event.dest_path)


        return
   

   


class Watcher():

    def __init__(self, path):
        self.observer = Observer()
        self.path = path

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.path, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print("Error whith filesystem watchdog")

        self.observer.join()


# return true if it is sensible data
def isSensible(name):

    if (".key" in name or ".pem"):  #TODO: do better
        return True
    
    return False

# encrypt the data, store it in a file and output the path to this file
def get_encrypted_path(path):

    f = open(path, 'rb')

    data = f.read(BUFFER_SIZE)

    buff = data

    while(data):
        data = f.read(BUFFER_SIZE)
        buff += data


    encrypted = encrypt(backup_key_path, buff)

    enc = open(HOME_DIR+"tmp_encrypted", 'wb')

    enc.write(encrypted)

    f.close()
    enc.close()

    return HOME_DIR+"tmp_encrypted"


def launch_backup(name, path):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

            with context.wrap_socket(sock, server_hostname=BACKUP_IP) as ssock:

                ssock.settimeout(0.3)

                try:

                    ssock.connect((BACKUP_IP, BACKUP_PORT))

                    #first send name of modified file

                    ssock.send(name.encode())            
                    print("name sent. Name is : "+name)

                    file_path = path    #original path to copy data from

                    if isSensible(name):    #encrypt if needed
                        file_path = get_encrypted_path(path)


                    #then send the data
                    f = open(file_path, 'rb')            

                    data = f.read(BUFFER_SIZE)
                    
                    while(data):

                        ssock.send(data)
                        data = f.read(BUFFER_SIZE)

                    print("backup finished")
                    f.close()

                    if isSensible(name) :    #remove temp file
                        remove(file_path)
                    
                except Exception as e:
                    print(e)
                    print('error occured while performing backup')

                ssock.shutdown(socket.SHUT_RDWR)
                ssock.close()
                return

#############Backup Agent##############

#launch watchers for each file or directory
w = Watcher(CERTS)
w.run()

