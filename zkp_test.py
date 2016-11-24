from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from paillier import *
from Crypto.Random.random import getrandbits
import fractions
import Crypto

sk, pk = generate_keypair(128)

m = long(0)
print "m is " + str(m)
g = pk.g
n = pk.n
n2 = pk.n_sq
x = long(get_x(pk))
c = encrypt(pk, x, m)
print "c is " + str(c)
d = decrypt(sk, pk, c)
print "d is " + str(d)

r = long(getrandbits(16))
r = long(r % pk.n)
s = long(getrandbits(16) % pk.n)
# maybe s in Zstar n
u = (pow(g, r, n2) * pow(s, n, n2)) % n2 

#select e
e = 10

v = (r - (e * m)) % n2
w = s * pow(x, ((-e) % n2), n2) * pow(g, (v/n), n2)



print "u is " + str(u)
check = (pow(g,v,n2) * pow(c,e,n2) * pow(w,n,n2)) % n2
print "u is " + str(check)
# u and check should be the same... but are not...
print "Are they equal? If so, pass zkp"
