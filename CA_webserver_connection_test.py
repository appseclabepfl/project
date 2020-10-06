from CA_link import *

#TESTS

print(getCAStats())

getNewCert('/home/webserver/test.txt', 'user1')

revokeCert('user1')
