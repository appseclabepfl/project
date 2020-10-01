#CA server that listens for incoming requests from the webserver
#The functions triggered match the system requirements as described in the "assignment" file
#CA ip : 10.10.10.3, webserver ip: 10.20.20.2



import socket
import ssl
from threading import Thread


webserver_IP= '10.20.20.2'
CA_IP = '10.10.10.3'
port = 5000

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/path/to/certchain.pem', '/path/to/private.key')       #TODO create valid certs and put them on the VMs

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:

    sock.bind((CA_IP, port))
    sock.listen(5)

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
    cert_OK = 'newcertificateOK'
    cert_FAIL = 'newcertificateFAIL'

    request = conn.recv(1024)

    if request == revoke_cert:

        #lauch revocation process

        #TODO send back confirmation of revocation or failure message

        conn.sendTo(revoke_OK, webserver_IP)


    elif request == new_cert:

        #launch creation of new certificate


        #send the certificate

        cert_path = '/home'         #TODO put path to certificate
        f = open(cert_path, 'rb')

        data = f.read(1024)

        while (data):         
            conn.sendAll(data)
            data = f.read(1024)

        f.close()

        conn.sendTo(cert_OK, webserver_IP)


    elif request == stats:

        #display stats about the CA

        #TODO send back the stats
        stats = 'CA stats....'

        conn.sendTo(stats, webserver_IP)


    else:

        print("Invalid instruction")

    conn.close()

    return





       

