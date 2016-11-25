# Initialization for demo

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256

from paillier import *

# Generate key pair
sk, pk = generate_keypair(128)

# Save public key
f1 = open('publickey.txt', 'w')
f1.write(str(pk.n))
f1.close()
# Save private key
f2 = open('secretkey.txt', 'w')
f2.write(str(sk.l) + " " + str(sk.m))
f2.close()

####################################

# Create and store hashes of verified voters
voters = ['a', 'b', 'c', 'd', 'e', 'f']
f = open('hashes.txt', 'w')
count = 0
for person in voters:
    h = SHA256.new()
    h.update(person)
    if count == 0:
        data = h.hexdigest()
    else:
        data = data + ' ' + h.hexdigest()
    count = count + 1
f.write(data)
f.close()

####################################


    
