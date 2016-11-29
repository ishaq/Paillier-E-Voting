
# simulation voter

"""
Voter

This module represents a voting booth. The user enters his name, PIN and choice of the candidate. This module encrypts
the vote and gets it blind-signed from Election Board (EM). The vote is then cast to the Bulletin Board (BB).
"""

import socket

from Crypto.Random import random
from paillier import paillier

import config
import common
import em_interface
import bb_interface


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
    
    
    # Voting Loop
    while True:
        voter_id = simfile.readline().rstrip('\n')
        voter_pin = simfile.readline().rstrip('\n')

        vote = -1
        while vote < 0 or vote > (config.NUM_CANDIDATES - 1):
            vote_str = simfile.readline().rstrip('\n')
            try:
                vote = int(vote_str)
            except ValueError:
                continue

        print("\n{}, You are voting for candidate: {}.".format(voter_id, vote))
        choice = simfile.readline().rstrip('\n')
        if not choice[0].lower() == "y":
            continue

        print("Submitting your vote, please wait...")
        enc_vote = _encrypt_vote(vote, pub_keys)
        r, blind_enc_vote = _blind_encrypted_vote(enc_vote, pub_keys)
        resp = _get_blind_sign_from_em(voter_id, voter_pin, blind_enc_vote)

        if resp is None:
            continue
        unblinded_sign = pub_keys.rsa_pub_key.unblind(resp.signed_blinded_encrypted_vote, r)
        if not pub_keys.rsa_pub_key.verify(enc_vote, (unblinded_sign,)):
            print("Error: EM blind signature did NOT verify. Try again.")
            continue

        cast_vote_response = _cast_vote_to_bb(enc_vote, unblinded_sign)
        if cast_vote_response is None:
            print("Error: an error occurred while casting vote. Try again.")
            continue

        print("\n\nSUCCESS.")

        if isinstance(cast_vote_response, bb_interface.RespVotingClosed):
            print("\n\nVoting session is now over. Please check Election Board (EM) for results.")
            break;
        else:
            print("\n\nNext Voter:")
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
    return None


def _cast_vote_to_bb(enc_vote, signed_enc_vote):
    sock_to_bb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_bb.connect(config.BB_ADDR)
    req = bb_interface.ReqCastVote(enc_vote, signed_enc_vote)
    common.write_message(sock_to_bb, req)
    resp = common.read_message(sock_to_bb)
    print("Response for Cast Vote: {}".format(resp))

    # TODO: ZKP loop

    if isinstance(resp, bb_interface.RespCastVoteSuccess) or isinstance(resp, bb_interface.RespVotingClosed):
        return resp
    return None


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
    encrypted_vote = paillier.encrypt(pub_keys.paillier_pub_key, shifted_vote)
    print("vote: {}, shifted_vote: {}, encryped_vote: {}".format(vote, shifted_vote, encrypted_vote))
    return encrypted_vote

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
