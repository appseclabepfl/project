from CA_link import *
from OpenSSL import crypto
#TESTS

print(getCAStats())

getNewCert('/home/webserver/test.p12', 'userTest')

# Load PKCS#12 and extract certificate
p12 = crypto.load_pkcs12(open('/home/webserver/test.p12', 'rb').read())
cert = crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_certificate())

# Test verify_certificate
verify_certificate(cert)

status = revokeCert('userTest')

assert(status == 0)
