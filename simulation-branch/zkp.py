"""
Zero Knowledge Proof (ZKP)

This module contains utility methods for zero knowledge proofs. Note that we are not using the
ZKP discussed in class since that ZKP does not prove correctness of the vote. We *did* write that
ZKP and it is available in zkp_test.py. This ZKP from https://www.codelabs.ch/paillier-zkp/paillier-zkp-slides.pdf
"""

from Crypto.Random import random
from paillier import paillier


def compute_valid_messages(num_candidates, max_votes):
    """
    computes all valid vote messages

    :param num_candidates: number of candidates
    :param max_votes: maximum votes that a candidate can get (e.g. number of total voters, though it's
     unlikely a single candidate would get all the votes)
    :return: a list of valid vote messages (each item represents a vote for candidate at that index)
    """

    bits_per_candidate = max_votes.bit_length()
    valid_messages = [1 << (x * bits_per_candidate) for x in range(num_candidates)]
    print(" valid_messages: {}".format(valid_messages))
    return valid_messages


def compute_inv_gmk(g, n, valid_messages):
    """
    Computes $$g^{-m_k}$$ for all valid messages
    :param g: generator of Paillier PK
    :param n: N of Paillier PK
    :param valid_messages: all valid vote messages
    :return: a list, each item is $$g^{-m_k}$$ for message at index k
    """
    n_sq = n * n
    inv_g = paillier.modinv(g, n_sq)
    print("inv_g: {}".format(inv_g))
    inv_gmk_params = [pow(inv_g, m, n_sq) for m in valid_messages]
    print("inv_gmk_params: {}".format(inv_gmk_params))
    return inv_gmk_params


def compute_e_max(n):
    """
    computes $$e_{max}$$

    :param n: N of Paillier PK
    :return: $$e_{max}$$
    """

    # $$e_{max}$$ is the half of public key n's bit-length
    e_max = 1 << ((n.bit_length() >> 1) - 1)
    print("n.bit_length(): {}, e_max.bit_length(): {}, e_max: {}".format(n.bit_length(), e_max.bit_length(), e_max))
    return e_max


def select_e_s(e_max):
    """
    select e_s (secret e)

    e_s is chosen by the Verifier to challenge Prover

    :param e_max: maximum e
    :return: e_s
    """
    e_s = random.randint(0, e_max)
    print("e_s: {}".format(e_s))
    return e_s


def compute_u_params(c, inv_gmk_params, n_sq):
    """
    computes $$u_k$$

    :param c: cipher text
    :param inv_gmk_params: $$g^{-m_k}$$ for all valid messages
    :param n_sq: N^2 of Paillier PK
    :return: a list, each item is $$u_k$$ for index k
    """
    u_params = [0] * len(inv_gmk_params)
    for i in range(len(inv_gmk_params)):
        u = (c * inv_gmk_params[i]) % n_sq
        u_params[i] = u
    print("u_params: {}".format(u_params))
    return u_params


def compute_pre_commitment_params(m, valid_messages, e_max, u_params, pk):
    """
    computes paramters before Prover makes a commitment

    these parameters are w (omega). a, z, e. a, z, and e are lists

    :param m: the message corresponding to the cipher text (the vote)
    :param valid_messages:  all valid messages
    :param e_max: e_max
    :param u_params: u_params
    :param pk: public key of Paillier
    :return: a tuple (w, a_params, z_params, e_params)
    """

    inv_u_params = [paillier.modinv(u, pk.n_sq) for u in u_params]
    print("inv_u_params: {}".format(inv_u_params))

    l = len(valid_messages)
    a_params = [0] * l
    z_params = [0] * l
    e_params = [0] * l

    w = paillier.get_r_in_z_n_star(pk)

    msg_index = 0

    for i in range(l):
        if m == valid_messages[i]:
            msg_index = i
            a_params[i] = pow(w, pk.n, pk.n_sq)
            # not computing z_i and e_i yet, will be computed when e_s is revealed
        else:
            e_params[i] = random.randint(0, e_max)
            z_params[i] = paillier.get_r_in_z_n_star(pk)
            a_params[i] = pow(z_params[i], pk.n, pk.n_sq) * pow(inv_u_params[i], e_params[i], pk.n_sq) % pk.n_sq

    print("msg_index: {}".format(msg_index))
    print("omega: {}".format(w))
    print("a_params: {}".format(a_params))
    print("z_params: {}".format(z_params))
    print("e_params: {}".format(e_params))
    return msg_index, w, a_params, z_params, e_params


def compute_challenge_response_params(msg_index, e_max, e_s, e_params, z_params, w, r, pk):
    """
    Computes parameters to satisfy Verifier's challenge

    :param msg_index: index of the msg in valid_messages
    :param e_max: e_max
    :param e_s: e_s sent by the Verifier
    :param e_params: e_params
    :param z_params: z_params
    :param w: omega
    :param r: random number used to encrypt the message
    :param pk: public key of Paillier
    :return: a tuple (e_params, z_params)
    """

    e_params[msg_index] = 0
    z_params[msg_index] = 0

    e_sum = 0
    for e in e_params:
        e_sum = (e_sum + e) % e_max

    e_params[msg_index] = (e_s - e_sum) % e_max
    print("e_i: {}".format(e_params[msg_index]))
    z_params[msg_index] = (w * pow(r, e_params[msg_index], pk.n_sq)) % pk.n_sq
    print("z_i: {}".format(z_params[msg_index]))
    print("e_params: {}".format(e_params))
    print("z_params: {}".format(z_params))

    return e_params, z_params


def verify(e_max, e_s, a_params, e_params, z_params, u_params, pk):
    """
    Verifies the prover's ZKP

    :param e_max: e_max
    :param e_s: e_s
    :param a_params: a_params
    :param e_params: e_params
    :param z_params: z_params
    :param u_params: u_params
    :param pk: public key of Paillier
    :return: True/False, result of ZKP verification
    """
    e_sum = 0
    for e in e_params:
        e_sum = (e_sum + e) % e_max
    l = len(e_params)

    print("e_sum: {}, correct: {}".format(e_sum, (e_sum % e_max) == e_s))
    if (e_sum % e_max) != e_s:
        print("e_sum is not expected, ZKP failed")
        return False

    # and the equation z_params[i]^n = u_params[i]^e_params[i] * a_params[i] holds
    for i in range(l):
        z_n = pow(z_params[i], pk.n, pk.n_sq)
        rhs = (pow(u_params[i], e_params[i], pk.n_sq) * a_params[i]) % pk.n_sq
        print("z_n: {}, rhs: {}, correct: {}", z_n, rhs, z_n == rhs)
        if z_n != rhs:
            return False

    print("ZKP Result Passed")
    return True

