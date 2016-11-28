from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from paillier import *
from Crypto.Random.random import getrandbits
import fractions
import Crypto

sk, pk = generate_keypair(16)

m = long(6)
print "m is " + str(m)
g = pk.g
n = pk.n
n2 = pk.n_sq
x = long(get_x(pk))
print("g: {}, n: {}, n^2: {}, x: {}".format(g, n, n2, x))
c = encrypt(pk, x, m)
print "c is " + str(c)
d = decrypt(sk, pk, c)
print "d is " + str(d)

# r is the message
r = long(8)
# s is the random number
s = get_x(pk)
# u is actually encryption of r with random s i.e. m = r, and x = s
u = encrypt(pk, s, r)

print("r: {}, s: {}, u: {}, decryption of u: {}".format(r, s, u, decrypt(sk, pk, u)))

#select e
e = long(10)


v = (r - (e * m)) % n2
inv_x = invmod(x, n2)
w = (s * pow(inv_x, e, n2)) % n2
print("e: {}, v: {}, w: {}".format(e, v, w))



print "u is " + str(u)
check = (pow(g,v,n2) * pow(c,e,n2) * pow(w,n,n2)) % n2
print "check is " + str(check)
# u and check should be the same... but are not...
print("Did ZKP Succeed? {}".format(check == u))
