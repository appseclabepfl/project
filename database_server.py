#!/usr/bin/python
import socket
import ssl
import base64
import mysql.connector.pooling
import json
from threading import Thread

# TLS Constants
WEBSERVER_IP = '10.10.20.2'
DATABASE_IP = '10.10.10.2'
PORT = 42069
BUFFER_SIZE = 1024

# Supported operations
CHECK_PASSWORD = 'CHECK_PASSWORD'
GET_USER_DATA = 'GET_USER_DATA'
UPDATE_USER_DATA = 'UPDATE_USER_DATA'

# Error messages
NO_DB_CNX = 'No database connection available'

dbconfig = {
    "host": "localhost",
    "port": "3306",
    "user": "webserver",
    "password": "a$V&kG!He7z-q#XV",
    "database": "imovies_users",
    "charset": "utf8"
}

cnxpool = mysql.connector.pooling.MySQLConnectionPool(pool_name="webserver_pool", pool_size=5, **dbconfig)

# Returns code 0 on success, 1 on non matching hashes or error
def check_password(username_password, cnx):
    username, password = base64.b64decode(username_password).split(':')

    sql_prepared_statement = """SELECT pwd FROM users WHERE uid = %s"""
    cursor = cnx.cursor(prepared=True)

    try:
        cursor.execute(sql_prepared_statement, (username,))
        db_password = cursor.fetchone()[0].decode()
    except mysql.connector.Error as e:
        #print("Error: " + e.msg)
        return "1"

    if password == db_password:
        return "0"
    else:
        return "1"

# Returns a JSON with the user data if any along with response code 0,
# or empty JSON with response code 1 and error message if no matching user or error
def get_user_data(username, cnx):

    sql_prepared_statement = """SELECT uid, lastname, firstname, email FROM users WHERE uid = %s"""
    cursor = cnx.cursor(prepared=True)

    try:
        cursor.execute(sql_prepared_statement, (base64.b64decode(username),))
        user_data = cursor.fetchone()

        try:
            json_response = {
                "uid": user_data[0].decode(), "lastname": user_data[1].decode(),
                "firstname": user_data[2].decode(), "email": user_data[3].decode(),
                "response_code": "0", "error_msg": ""
            }
        except Exception as e:
            json_error = {
                "uid": "", "lastname": "",
                "firstname": "", "email": "",
                "response_code": "1", "error_msg": "No such user"
            }
            return json.dumps(json_error)

    except mysql.connector.Error as e:
        #print("Error: " + e.msg)
        json_error = {
            "uid": "", "lastname": "",
            "firstname": "", "email": "",
            "response_code": "1", "error_msg": e.msg
        }
        return json.dumps(json_error)

    return json.dumps(json_response)


def update_user_data(json_payload, cnx):

    cursor = cnx.cursor(prepared=True)

    # 2 scenarii upon information update:
    # On UPDATE INFORMATION page only uid, firstname, lastname and email are displayed
    #   1: password field is empty because password did not change
    #   2: password field is not empty because password did change
    try:
        if json_payload["pwd"] == "":
            sql_prepared_statement = """ UPDATE users SET uid=%s, lastname=%s, firstname=%s, email=%s WHERE uid=%s"""
            params = (json_payload["uid"], json_payload["lastname"],
                      json_payload["firstname"], json_payload["email"],
                      json_payload["uid"])

            try:
                cursor.execute(sql_prepared_statement, params)
                cnx.commit()
            except mysql.connector.Error as e:
                return "MySQL Error: "+e.msg

        else:
            sql_prepared_statement = """ UPDATE users SET uid=%s, lastname=%s, firstname=%s,
                                        email=%s, pwd=%s WHERE uid=%s"""
            params = (json_payload["uid"], json_payload["lastname"],
                      json_payload["firstname"], json_payload["email"],
                      json_payload["pwd"], json_payload["uid"])
            try:
                cursor.execute(sql_prepared_statement, params)
                cnx.commit()
            except mysql.connector.Error as e:
                return "MySQL Error: " + e.msg
    except Exception as e:
        return "Error in the JSON format, missing or mistyped field name. Error: "+e.message

    return "Update successful !"


def serve(conn):

    request = conn.recv(BUFFER_SIZE)
    request = request.decode()

    #print("GOT REQUEST: "+request)

    try:
        cnx = cnxpool.get_connection()
    except mysql.connector.errors.PoolError as e:
        #print(e.msg)
        conn.send(NO_DB_CNX.encode())
        conn.close()
        return

    if request == CHECK_PASSWORD:
        conn.send("Serving for CHECK_PASSWORD".encode())
        # username and password hash format: username:hashedpassword in base64
        username_password = conn.recv(BUFFER_SIZE)
        conn.send(check_password(username_password.decode(), cnx).encode())
    elif request == GET_USER_DATA:
        conn.send("Serving for GET_USER_DATA".encode())
        # username format: username in base64
        username = conn.recv(BUFFER_SIZE)
        conn.send(get_user_data(username, cnx).encode())
    elif request == UPDATE_USER_DATA:
        conn.send("Serving for UPDATE_USER_DATA".encode())
        try:
            raw_payload = json.loads(conn.recv(BUFFER_SIZE))
            conn.send(update_user_data(raw_payload, cnx).encode())
        except Exception as e:
            conn.send("Error in the json payload format.".encode())
    else:
        conn.send("Invalid command".encode())

    cnx.close()
    conn.close()

    return


class ClientThread(Thread):

    def __init__(self, connection):
        Thread.__init__(self)
        self.conn = connection

    def run(self):
        serve(self.conn)
        return

#### SERVER ####

context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
context.verify_mode = ssl.CERT_REQUIRED
context.options |= (ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.load_cert_chain('/home/database/database_TLS.pem', '/home/database/database_TLS.key')       #Path to certificates for TLS comunication
context.load_verify_locations('/home/database/rootCA.pem')      #path to certificate for TLS
context.set_ciphers('ECDHE-RSA-AES256-SHA384')


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((DATABASE_IP, PORT))
sock.listen(5)

ssock = context.wrap_socket(sock, server_side=True)

while True:

    # accept connections
    (conn, address) = ssock.accept()

    conn.settimeout(0.3)

    #print('Connection received from ' + str(address))

    if address[0] != WEBSERVER_IP:  # reject ip that are not the webserver
        conn.close()

    else:  # dispatch threads

        try:
            t = ClientThread(conn)
            t.start()
        except:
            #print('Error when processing request')
