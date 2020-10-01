#CA server that listens for incoming requests from the webserver
#The functions triggered match the system requirements as described in the "assignment" file
#CA ip : 10.10.10.3, webserver ip: 10.20.20.2



import socket
import ssl
from threading import Thread


webserver_IP= '10.20.20.2'
CA_IP = '10.10.10.3'
port = 5000

BUFFER_SIZE = 1024

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('../keys_and_certs/CA_certificate.pem', '../keys_and_certs/CA_TLS_pk.key')       #TODO create valid certs and put them on the VMs

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

    sock.bind((CA_IP, port))
    sock.listen(5)              #TODO how many concurrent connnections are we expecting ?

    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()

        while True:

            # accept connections
            (conn, address) = ssock.accept()

            if address != webserver_IP:      #reject ip that are not the webserver  TODO verify that it works as intended
                conn.close()

            else:   #dispatch threads
                
                Thread(target=serve, args=(conn,)).start()
                


#function that will communicate with the webserver and call the core CA functions
def serve(conn):

    #operations supported by the server

    revoke_cert = 'REVOKE'
    new_cert = 'NEW'
    stats = 'STATS'

    #messages sent by server

    revoke_OK = 'revocationOK'
    revoke_FAIL = 'revocationFAIL'


    request = conn.recv(BUFFER_SIZE)

    if request == revoke_cert:      #lauch revocation process

        userInfo = conn.recv(BUFFER_SIZE)

        #TODO REVOKE CERTIFICATES HERE

        

        #TODO send back confirmation of revocation or failure message

        conn.sendTo(revoke_OK, webserver_IP)


    elif request == new_cert:       #launch creation of new certificate

        #listen for user informations (should be less than 1024 byte)

        userInfo = conn.recv(BUFFER_SIZE)

        #TODO GENERATE CERTIFICATE HERE 

        #send the certificate

        cert_path = '/home'         #TODO put path to certificate
        f = open(cert_path, 'rb')

        data = f.read(BUFFER_SIZE)

        while (data):         
            conn.sendAll(data)
            data = f.read(BUFFER_SIZE)

        f.close()


    elif request == stats:

        #display stats about the CA

        #TODO send back the stats
        stats = 'CA stats....'

        conn.sendTo(stats, webserver_IP)


    else:

        print("Invalid instruction")

    conn.close()

    return
