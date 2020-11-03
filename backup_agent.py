#script that will monitor folders and files and perform backup upon change


import socket
import ssl
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from os.path import basename


#SSL connection

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/coreca/CA_certificate.pem', '/home/coreca/CA_TLS_pk.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/coreca/rootCA.pem')      #path to certificate for TLS 
context.set_ciphers('ECDHE-RSA-AES256-SHA384')
    
BACKUP_IP = '10.10.10.4'
BACKUP_PORT = 5555

BUFFER_SIZE = 1024


#Path to watch

HOME_DIR = '/home/coreca'




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
            launch_backup(basename(event.src_path), event.dst_path)


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





def launch_backup(name, path):

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

            with context.wrap_socket(sock, server_hostname=BACKUP_IP) as ssock:

                ssock.settimeout(0.3)

                try:

                    ssock.connect((BACKUP_IP, BACKUP_PORT))

                    #first send name of modified file

                    ssock.send(name.encode())            
                    print("name sent. Name is : "+name)

                    #then send the data

                    f = open(path, 'rb')            #TODO encrypt  before sending data

                    data = f.read(BUFFER_SIZE)
                    
                    while(data):

                        ssock.send(data)
                        data = f.read(BUFFER_SIZE)

                    print("backup finished")
                    f.close()

                    
                except Exception as e:
                    print(e)
                    print('error occured while performing backup')

                ssock.shutdown(socket.SHUT_RDWR)
                ssock.close()
                return

#############Backup Agent##############

#launch watchers for each file or directory
w = Watcher(HOME_DIR)
w.run()

