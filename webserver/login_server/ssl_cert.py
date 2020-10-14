import ssl

def setup():
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) # TODO TLS 1.3? -> not available in this library
    context.load_cert_chain('cert/server.crt', 'cert/server.key')
    return context