from CA_link import *

#TESTS

print(getCAStats())

getNewCert('/home/webserver/test.p12', 'userTest')

status = revokeCert('userTest')

assert(status == 0)
