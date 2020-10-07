#CA server that listens for incoming requests from the webserver
#The functions triggered match the system requirements as described in the "assignment" file
#CA ip : 10.10.10.3, webserver ip: 10.20.20.2



import socket
import ssl
from threading import Thread

webserver_IP= '10.10.20.2'
CA_IP = '10.10.10.3'
port = 6000
BUFFER_SIZE = 1024


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
    




#function that will communicate with the webserver and call the core CA functions
def serve(conn):

    #operations supported by the server
    revoke_cert = 'REVOKE'
    new_cert = 'NEW'
    stats = 'STATS'

    #messages sent by server
    revoke_OK = 'revocationOK'
    revoke_FAIL = 'revocationFAIL'

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

        userInfo = conn.recv(BUFFER_SIZE)
        
        try:
            #TODO REVOKE CERTIFICATES HERE
            print(userInfo.decode())
        
        except:
            conn.send(revoke_FAIL.encode())

        conn.send(revoke_OK.encode())


    elif request.decode() == new_cert:       #launch creation of new certificate

        #listen for user informations (should be less than 1024 byte)

        userInfo = conn.recv(BUFFER_SIZE)

        #TODO GENERATE CERTIFICATE HERE
        print(userInfo.decode()) 

        #send the certificate

        cert_path = '/home/coreca/test.crt'         #TODO put path to certificate
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
        




context = context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/coreca/CA_certificate.pem', '/home/coreca/CA_TLS_pk.key')       #Path to certificates for TLS communication
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

