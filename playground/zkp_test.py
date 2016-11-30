from Crypto.Random import random
import sys
sys.path.append('../')
from paillier import paillier

# --- KNOWLEDGE OF PLAIN TEXT ZKP ---
print("--- KNOWLEDGE OF PLAIN TEXT ZKP ---")
sk, pk = paillier.generate_keypair(16)
print("{}, {}".format(sk, pk))

m = 1
print("m is " + str(m))
g = pk.g
n = pk.n
n2 = pk.n_sq
x = paillier.get_r_in_z_n_star(pk)
print("g: {}, n: {}, n^2: {}, x: {}".format(g, n, n2, x))
c = paillier.encrypt_with_r(pk, x, m)
print("c is " + str(c))
d = paillier.decrypt(sk, pk, c)
print("d is " + str(d))

# r is the message
r = 8
# s is the random number
s = paillier.get_r_in_z_n_star(pk)
# u is actually encryption of r with random s i.e. m = r, and x = s
u = paillier.encrypt_with_r(pk, s, r)

print("r: {}, s: {}, u: {}, decryption of u: {}".format(r, s, u, paillier.decrypt(sk, pk, u)))

# select e
e = 10


v = (r - (e * m)) % n2
# w = s * pow(x^{-1}, e, n2) * pow(g, (v/n), n2)
inv_x = paillier.modinv(x, pk.n_sq)
w = (s * pow(inv_x, e, n2)) % n2
print("e: {}, v: {}, w: {}".format(e, v, w))



print("u is " + str(u))
check = (pow(g, v, n2) * pow(c, e, n2) * pow(w, n, n2)) % n2
print("check is " + str(check))
# u and check should be the same... but are not...
print("Did ZKP Succeed? {}".format(check == u))


# ---  WELL FORMEDNESS ZKP ---
print("--- WELL FORMEDNESS ZKP ---")

NUM_VOTERS = 100
NUM_CANDIDATES = 5
bits_per_candidate = NUM_VOTERS.bit_length()
key_size = NUM_CANDIDATES * bits_per_candidate
if key_size % 2 == 1:
    key_size += 1

sk, pk = paillier.generate_keypair(key_size)
print("bits_per_candidate: {}, key_size: {}, {}, {}".format(bits_per_candidate, key_size, sk, pk))
valid_messages = [1 << (x*bits_per_candidate) for x in range(NUM_CANDIDATES)]
print(" valid_messages: {}".format(valid_messages))

msg = valid_messages[0]
rand = paillier.get_r_in_z_n_star(pk)
cipher = paillier.encrypt_with_r(pk, rand, msg)
print("msg: {}, rand: {}, cipher: {}".format(msg, rand, cipher))


# BOTH
# Both sides compute u_params (BB can pre-compute inv_gmk_params for all valid messages)
inv_g = paillier.modinv(pk.g, pk.n_sq)
print("inv_g: {}".format(inv_g))
inv_gmk_params = [pow(inv_g, m, pk.n_sq) for m in valid_messages]
print("inv_gmk_params: {}".format(inv_gmk_params))
# e_max is the half of public key n's bit-length
e_max = 1 << ((pk.n.bit_length() >> 1) - 1)
print("pk.n.bit_length(): {}, e_max.bit_length(): {}, e_max: {}".format(pk.n.bit_length(), e_max.bit_length(), e_max))

u_params = [0] * NUM_CANDIDATES
for i in range(NUM_CANDIDATES):
    u = (cipher * inv_gmk_params[i]) % pk.n_sq
    u_params[i] = u

print("u_params: {}".format(u_params))


# PROVER
print("PROVER")
# prover needs inverse uks too
inv_u_params = [paillier.modinv(u, pk.n_sq) for u in u_params]
print("inv_u_params: {}".format(inv_u_params))


# Prover: creates a_ks (including a_i) and e_i
a_params = [0] * NUM_CANDIDATES
z_params = [0] * NUM_CANDIDATES
e_params = [0] * NUM_CANDIDATES

w = paillier.get_r_in_z_n_star(pk)

vote_i = 0

for i in range(NUM_CANDIDATES):
    if msg == valid_messages[i]:
        vote_i = i
        a_params[i] = pow(w, pk.n, pk.n_sq)
        # not computing z_i and e_i yet, will be computed when e_s is revealed
    else:
        e_params[i] = random.randint(0, e_max)
        z_params[i] = paillier.get_r_in_z_n_star(pk)
        a_params[i] = pow(z_params[i], pk.n, pk.n_sq) * pow(inv_u_params[i], e_params[i], pk.n_sq) % pk.n_sq

print("vote_i: {}".format(vote_i))
print("omega: {}".format(w))
print("a_params: {}".format(a_params))
print("z_params: {}".format(z_params))
print("e_params: {}".format(e_params))

# Prover sends over a_k (including a_i)

# VERIFIER
print("VERIFIER")

e_s = random.randint(0, e_max)
print("e_s: {}".format(e_s))
# Verifier sends e_s

# PROVER
print("PROVER")
# Prover computes e_i, z_i
e_sum = 0
for e in e_params:
    e_sum += e

e_sum %= e_max
e_params[vote_i] = e_max - e_sum
print("e_i: {}".format(e_params[vote_i]))
z_params[vote_i] = (w * pow(rand, e_params[vote_i], pk.n_sq)) % pk.n_sq
print("z_i: {}".format(z_params[vote_i]))
print("e_params: {}".format(e_params))
print("z_params: {}".format(z_params))

# Prover sends all e_params and all z_params

# VERIFIER
print("PROVER")
# Verifier checks that e_is add to to e_s
e_sum = 0
for e in e_params:
    e_sum += e

print("e_sum: {}, correct: {}".format(e_sum, (e_sum % e_max) == 0))
# and the equation z_params[i]^n = u_params[i]^e_params[i] * a_params[i] holds
well_formed_vote = True
for i in range(NUM_CANDIDATES):
    z_n = pow(z_params[i], pk.n, pk.n_sq)
    rhs = (pow(u_params[i], e_params[i], pk.n_sq) * a_params[i]) % pk.n_sq
    print("z_n: {}, rhs: {}, correct: {}", z_n, rhs, z_n == rhs)
    if z_n != rhs:
        well_formed_vote = False
        break


zkp_result = ((e_sum % e_max) == 0) and well_formed_vote
print("ZKP Result: {}".format(zkp_result))


