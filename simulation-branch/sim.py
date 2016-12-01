"""
Voter

This module represents a voting booth. The user enters his name, PIN and choice of the candidate. This module encrypts
the vote and gets it blind-signed from Election Board (EM). The vote is then cast to the Bulletin Board (BB).
"""

import socket

from Crypto.Hash import SHA256
from Crypto.Random import random
from paillier import paillier

import config
import common
import em_interface
import bb_interface
import zkp


def setup():
    """
    Stub to setup Voter, doesn't do anything useful right now
    """

    print("Voter setup complete...")


def kick_off():
    """
    Kicks off the Voter

    Prepares itself for voters
    """

    pub_keys = common.get_public_key_from_em()
    simfile = open("sim.txt", "r")
    print("\n\n\nREADY!\n")
    # Voting Loop
    while True:
        voter_id = simfile.readline().rstrip('\n')
        voter_pin = simfile.readline().rstrip('\n')

        candidate_index = -1
        while candidate_index < 0 or candidate_index > (config.NUM_CANDIDATES - 1):
            vote_str = simfile.readline().rstrip('\n').format(config.NUM_CANDIDATES - 1)
            try:
                candidate_index = int(vote_str)
            except ValueError:
                continue

        print("\n{}, You are voting for candidate: {}.".format(voter_id, candidate_index))
        choice = simfile.readline().rstrip('\n')
        if not choice.lower() == "y":
            continue

        print("Submitting your vote, please wait...")
        vote, enc_vote, rand = _encrypt_vote(candidate_index, pub_keys)
        r, blind_enc_vote = _blind_encrypted_vote(enc_vote, pub_keys)
        resp = _get_blind_sign_from_em(voter_id, voter_pin, blind_enc_vote)

        if resp is None:
            continue

        unblinded_sign = pub_keys.rsa_pub_key.unblind(resp.signed_blinded_encrypted_vote, r)
        if not pub_keys.rsa_pub_key.verify(enc_vote, (unblinded_sign,)):
            print("Error: EM blind signature did NOT verify. Try again.")
            continue

        cast_vote_response = _cast_vote_to_bb(vote, rand, enc_vote, unblinded_sign, pub_keys.paillier_pub_key)
        if isinstance(cast_vote_response, bb_interface.RespCastVoteSuccess):
            sha256 = SHA256.new()
            sha256.update(str(enc_vote).encode("utf-8"))
            vote_hash = sha256.hexdigest()
            print("\n\nSUCCESS! Your vote has been cast.")
            print("\nPlease take a note of your encrypted vote or its hash, you can use one of these to verify" +
                  " that your vote was included in election by:" +
                  "\n\t1. looking for it in the bulletin board and " +
                  "\n\t2. verifying the encrypted tally.")
            print("Hash: \t\t{}".format(vote_hash))
            print("Encrypted Vote: {}\n".format(enc_vote))
            if cast_vote_response.is_voting_complete:
                print("\nVoting process is now complete. Please switch to EM to see election results")
                break
        else:
            print("VOTER: ERROR: {}.".format(cast_vote_response))
            continue

        if isinstance(cast_vote_response, bb_interface.RespVotingClosed):
            print("\n\nVoting session is now over. Please check Election Board (EM) for results.")
            break;
        else:
            print("\n\n\nNext Voter:")

    simfile.close()
# --- Private ---

class VoterState:
    """
    A model to encapsulate voter state
    """
    def __init__(self):
        pass


def _get_blind_sign_from_em(voter_id, voter_pin, blinded_encrypted_vote):
    """
    Gets blind signature from EM

    :param voter_id: id of the current voter
    :param voter_pin: secret PIN of the current voter
    :param blinded_encrypted_vote: encrypted (paillier) and blinded (RSA) vote of the voter
    :return: blind signature response
    """
    sock_to_em = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_em.connect(config.EM_ADDR)
    req = em_interface.ReqBlindSign(voter_id, voter_pin, blinded_encrypted_vote)
    common.write_message(sock_to_em, req)
    resp = common.read_message(sock_to_em)
    print("Response for Blind Sign: {}".format(resp))
    if isinstance(resp, em_interface.RespBlindSign):
        return resp
    if isinstance(resp, common.RespError):
        print("\n\nFAILED! Your vote was not cast, Reason: {}\n".format(resp.msg))
    return None


def _cast_vote_to_bb(plain_vote, rand, enc_vote, signed_enc_vote, pk):
    sock_to_bb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_bb.connect(config.BB_ADDR)
    req = bb_interface.ReqCastVote(enc_vote, signed_enc_vote)
    common.write_message(sock_to_bb, req)
    # handle the zkp
    resp = _handle_zkp(sock_to_bb, plain_vote, enc_vote, rand, pk)

    return resp


def _handle_zkp(conn, vote, enc_vote, rand, pk):
    resp = common.read_message(conn)
    print("VOTER: Expecting request for ZKP Commitment: {}".format(resp))
    if not isinstance(resp, bb_interface.RespZKPProvideCommitment):
        return resp

    print("VOTER: Got request for Commitment")
    valid_messages = zkp.compute_valid_messages(config.NUM_CANDIDATES, config.NUM_VOTERS)
    inv_gmk_params = zkp.compute_inv_gmk(pk.g, pk.n, valid_messages)
    e_max = zkp.compute_e_max(pk.n)
    u_params = zkp.compute_u_params(enc_vote, inv_gmk_params, pk.n_sq)

    vote_i, w, a_params, z_params, e_params = zkp.compute_pre_commitment_params(vote, valid_messages, e_max, u_params,
                                                                                pk)
    req = bb_interface.ReqZKPChallenge(a_params)
    print("VOTER: Sending Commitment")
    common.write_message(conn, req)

    # Loop till we keep getting challenged
    resp = common.read_message(conn)
    while isinstance(resp, bb_interface.RespZKPChallenge):
        print("VOTER: Got challenge: {}".format(resp))
        e_s = resp.e_s

        e_params, z_params = zkp.compute_challenge_response_params(vote_i, e_max, e_s, e_params, z_params, w, rand, pk)
        req = bb_interface.ReqZKPVerify(e_params, z_params)
        print("VOTER: Sending request for verification {}".format(req))
        common.write_message(conn, req)
        resp = common.read_message(conn)

    return resp


def _encrypt_vote(vote, pub_keys):
    """
    Encrypts the vote

    :param vote: vote (index of the candidate being voted for)
    :param pub_keys: public keys
    :return: encrypted vote OR None
    """
    if vote < 0 or vote >= config.NUM_CANDIDATES:
        print("Invalid Vote: {}, has to be between 0 and {}".format(vote, config.NUM_CANDIDATES - 1))
        return None
    shifted_vote = 1 << (vote * config.NUM_VOTERS.bit_length())
    rand = paillier.get_r_in_z_n_star(pub_keys.paillier_pub_key)
    encrypted_vote = paillier.encrypt_with_r(pub_keys.paillier_pub_key, rand, shifted_vote)
    print("vote: {}, shifted_vote: {}, encryped_vote: {}".format(vote, shifted_vote, encrypted_vote))
    return shifted_vote, encrypted_vote, rand

def _blind_encrypted_vote(encrypted_vote, pub_keys):
    """
    Blinds the encrypted vote

    :param encrypted_vote: voter's encrypted vote (encrypted with paillier)
    :param pub_keys: public keys of EM
    :return: a tuple, random number r and blinded encrypted vote
    """
    r = random.randint(pub_keys.rsa_pub_key.n >> 100, pub_keys.rsa_pub_key.n)
    blinded_encrypted_vote = pub_keys.rsa_pub_key.blind(encrypted_vote, r)
    print("encrypted_vote: {}, r: {}, blinded_vote: {}".format(encrypted_vote, r, blinded_encrypted_vote))
    return r, blinded_encrypted_vote



if __name__ == "__main__":
    setup()
    kick_off()
