from CA_link import *

#TESTS

print(getCAStats())

getNewCert('/home/webserver/test.p12', 'userTest')

uid = login_with_certificate('/home/webserver/test.p12')

assert(uid == 'userTest')

revokeCert('userTest')

uid = login_with_certificate('/home/webserver/test.p12')

print(uid)

assert(uid == "")