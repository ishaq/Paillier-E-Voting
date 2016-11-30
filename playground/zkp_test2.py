"""
Pretty much the same wellformedness ZKP as in the other test file. But uses functions in zkp.py
"""

import sys
sys.path.append('../')
from paillier import paillier
import zkp


# ---  WELL FORMEDNESS ZKP ---
print("--- WELL FORMEDNESS ZKP ---")

NUM_VOTERS = 100
NUM_CANDIDATES = 5
bits_per_candidate = NUM_VOTERS.bit_length()
key_size = NUM_CANDIDATES * bits_per_candidate
if key_size % 2 == 1:
    key_size += 1
if key_size < 128:
    key_size = 128

sk, pk = paillier.generate_keypair(key_size)
print("bits_per_candidate: {}, key_size: {}, {}, {}".format(bits_per_candidate, key_size, sk, pk))
valid_messages = zkp.compute_valid_messages(NUM_CANDIDATES, NUM_VOTERS)

msg = valid_messages[0] # MODIFY THIS TO ANOTHER VALUE OR AN INVALID VALUE TO SEE THAT ZKP FAILS ON INVALID VALUES
rand = paillier.get_r_in_z_n_star(pk)
cipher = paillier.encrypt_with_r(pk, rand, msg)
print("msg: {}, rand: {}, cipher: {}".format(msg, rand, cipher))

# BOTH
# Both sides compute u_params (BB can pre-compute inv_gmk_params for all valid messages)
inv_gmk_params = zkp.compute_inv_gmk(pk.g, pk.n, valid_messages)
e_max = zkp.compute_e_max(pk.n)
u_params = zkp.compute_u_params(cipher, inv_gmk_params, pk.n_sq)


# PROVER
print("PROVER")
# prover needs inverse uks too

# Prover: creates a_ks (including a_i) and e_i
vote_i, w, a_params, z_params, e_params = zkp.compute_pre_commitment_params(msg, valid_messages, e_max, u_params, pk)

# Prover sends over a_k (including a_i)

# VERIFIER
print("VERIFIER")
e_s = zkp.select_e_s(e_max)

# PROVER
print("PROVER")
# Prover computes e_i, z_i
e_params, z_params = zkp.compute_challenge_response_params(vote_i, e_max, e_s, e_params, z_params, w, rand, pk)

# Prover sends all e_params and all z_params
# VERIFIER
print("PROVER")
# Verifier checks that e_is add to to e_s
zkp_result = zkp.verify(e_max, e_s, a_params, e_params, z_params, u_params, pk)
print("ZKP: {}".format(zkp_result))

