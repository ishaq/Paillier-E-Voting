from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Hash import SHA256

# REGISTRAR SIDE

# 1) Generate Key pair for all communication with Voter
# this is the key pair that will be generated by the Registrar

priv = RSA.generate(3072)
pub = priv.publickey()

print("REGISTRAR: RSA key pair generated")

# --------------------------


# VOTER SIDE
# voter will blind the message by calculate m' = m * r^e

# this message is some value (in our case it's a vote) that we need a signature
# for, but we don't want to reveal this value to the Registrar
msg = "some vote value"
print("VOTER: Message to sign is: {}".format(msg))

# 1) generate a random number
r = random.randint(pub.n >> 100, pub.n)
print("VOTER: Random r is: {}".format(r))
# 2) now blind the message (i.e. vote)
blinded_msg = pub.blind(msg, r)
print("VOTER: Blinded message: {}".format(blinded_msg))

# HASH VERSION
# In practice, mesasge's HASH is used for blind signatures
hash = SHA256.new()
hash.update(msg)
msg_hash = hash.digest()
print("VOTER: Message Hash is: {}".format(msg_hash))
# 2a1) Now we blind the hash
blinded_hash = pub.blind(msg_hash, r)
print("VOTER: Blinded hash is: {}".format(blinded_hash))

# 3) send this to the Registrar

# --------------------------

# REGISTRAR SIDE
# Registrar will receive the blinded message from Voter

# 1) create a blind sign
blind_sign = priv.sign(blinded_msg, 0)
print("REGISTRAR: Blind Signature (on msg) is: {}".format(blind_sign))

# HASH VERSION
blind_sign_on_hash = priv.sign(blinded_hash, 0)
print("REGISTRAR: Blind Signature (on hash) is: {}".format(blind_sign_on_hash))


# 2) send this blind sign to Voter


# --------------------------

# VOTER SIDE
# Voter receives the blind sign, creates unblinded sign from it and verifies that
# Registrar signed correct message

# 1) unblind the sign
unblinded_sign = pub.unblind(blind_sign[0], r)
print("VOTER: Unblinded Signature (on msg) is: {}".format(unblinded_sign))
# 2) verify that the sign is correct (note the second param to verify is a tuple)
is_sign_correct = pub.verify(msg, (unblinded_sign,))
print("VOTER: The sign (on msg) is correct: {}".format(is_sign_correct))

# HASH VERSION
unblinded_sign_on_hash = pub.unblind(blind_sign_on_hash[0], r)
print("VOTER: Unblinded Signature (on hash) is: {}".format(unblinded_sign_on_hash))
is_sign_correct_on_hash = pub.verify(msg_hash, (unblinded_sign_on_hash, ))
print("VOTER: The sign (on hash) is correct: {}".format(is_sign_correct_on_hash))
