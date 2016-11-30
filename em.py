"""
Election Board (EM)

This module has all RSA and Paillier secret keys. It also has the voter list (along with their secret PIN numbers. It
 blindly signs a vote to make it a valid ballot. At the end of voting, it uses its keys to decrypt the results
"""

import socket
import pickle

from Crypto.PublicKey import RSA
from paillier import paillier

import common
import config
from em_interface import *


ALL_VOTERS = {}
for i in range(config.NUM_VOTERS):
    voter_name_and_pin = "Voter{0:02d}".format(i)
    ALL_VOTERS[voter_name_and_pin] = voter_name_and_pin


def setup():
    """
    Setups up the server

    Generates Paillier and RSA keys and persists them to disk
    """
    try:
        state = _read_state()
        print("Existing state found, loading it: {}".format(state))
    except FileNotFoundError:
        print("No previous state found, creating new state")
        state = ElectionBoardState()

        # Generate Key (RSA)
        print("Generating RSA Key with size: {}".format(config.RSA_KEY_SIZE))
        state.rsa_private_key = RSA.generate(config.RSA_KEY_SIZE)

        # Generate Key (Paillier)
        bits_per_candidate = config.NUM_VOTERS.bit_length()
        key_size = config.NUM_CANDIDATES * bits_per_candidate
        if key_size < config.MIN_PAILLIER_KEY_SIZE:
            key_size = config.MIN_PAILLIER_KEY_SIZE
        if key_size % 2 == 1:
            key_size += 1
        print("Generating Paillier Key with size: {}".format(key_size))
        paillier_private_key, paillier_public_key = paillier.generate_keypair(key_size)
        state.paillier_private_key = paillier_private_key
        state.paillier_public_key = paillier_public_key

        print("Saving Keys (and other state)")
        _write_state(state)

    print("Election Board (EM) setup complete...")


def kick_off():
    """
    Kicks off the server

    creates/binds a socket and starts listening for requests
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(config.EM_ADDR)
    sock.listen()

    # Read the state
    state = _read_state()

    print("Election Board (EM) started ...")

    # Message Processing Loop
    while True:
        conn, addr = sock.accept()
        msg = common.read_message(conn)
        if not msg:
            # The client has sent an invalid message, we close the connection
            # NOTE: We could also transmit an explanatory message to the client here
            conn.close()
            continue
        _handle_message(msg, conn, state)
        conn.close()
        _write_state(state)


def shutdown():
    """
    Shuts down the server

    stops listening and shuts down sockets
    """

# --- Private ---

def _handle_message(msg, conn, state):
    """
    Handles the message as appropriate

    :param msg: message from the client socket
    :param conn: the client socket
    :param state: election board state
    :return:
    """

    print("Received Message is: {}".format(msg))
    if isinstance(msg, ReqPublicKeys):
        _handleReqPublicKeys(msg, conn, state)
    elif isinstance(msg, ReqBlindSign):
        _handleReqBlindSign(msg, conn, state)
    elif isinstance(msg, ReqDisplayResults):
        _handleReqDisplayResults(msg, conn, state)


def _handleReqPublicKeys(msg, conn, state):
    """
    handles request for public keys
    """
    resp = RespPublicKeys(state.rsa_private_key.publickey(), state.paillier_public_key)
    common.write_message(conn, resp)


def _handleReqBlindSign(msg, conn, state):
    """
    handles request for blind signature

    checks that user is a valid voter (exists and pin is correct) and creates blind signature
    """
    # is voting in progress
    if not state.voting_in_progress:
        common.write_message(conn, common.RespError("Voting is NOT open"))
        return
    # user does not exist
    if msg.voter_id not in ALL_VOTERS.keys():
        common.write_message(conn, common.RespError("Invalid Voter or PIN"))
        return
    # pin is not correct
    elif not ALL_VOTERS[msg.voter_id] == msg.voter_pin:
        common.write_message(conn, common.RespError("Invalid Voter or PIN"))
        return
    # already got a signed vote
    elif msg.voter_id in state.signed_voters.keys():
        common.write_message(conn, common.RespError("Voter already got a signed vote, will not sign again"))
        return

    # Sign the vote
    state.signed_voters[msg.voter_id] = True
    blind_sign = state.rsa_private_key.sign(msg.blinded_ecnrypted_vote, 0)
    resp = RespBlindSign(blind_sign[0])
    common.write_message(conn, resp)


def _handleReqDisplayResults(msg, conn, state):
    state.voting_in_progress = False
    decrypted_results = paillier.decrypt(state.paillier_private_key, state.paillier_public_key, msg.encrypted_results)
    print("Decrypted Results: {} ({:b})".format(decrypted_results, decrypted_results))
    candidate_votes = [0] * config.NUM_CANDIDATES
    mask = pow(2, config.NUM_VOTERS.bit_length()) - 1

    for i in range(config.NUM_CANDIDATES):
        votes_count = (decrypted_results >> (i * config.NUM_VOTERS.bit_length())) & mask
        print("{}: votes:{} ({:b})".format(i, votes_count, votes_count))
        candidate_votes[i] = votes_count

    print("Candidate Votes: {}".format(candidate_votes))

    max_votes = max(candidate_votes)
    winner_indices = []
    for i in range(config.NUM_CANDIDATES):
        if max_votes == candidate_votes[i]:
            winner_indices.append(i)

    if len(winner_indices) > 1:
        print("We have a tie between candidates: {}".format(winner_indices))
    else:
        print("Winner is candidate: {}".format(winner_indices[0]))


class ElectionBoardState:
    """
    A model to encapsulate Election Board (EM) state
    """
    def __init__(self):
        self.voting_in_progress = True
        self.rsa_private_key = None
        self.paillier_private_key = None
        self.paillier_public_key = None
        self.signed_voters = {}

    def __str__(self):
        rsa_public_key = None
        if self.rsa_private_key is not None:
            rsa_public_key = self.rsa_private_key.publickey()
        paillier_public_key_n = None
        if self.paillier_public_key is not None:
            paillier_public_key_n = self.paillier_public_key.n
        return "<ElectionBoardState: {}, {}, {}, {}>".format(self.voting_in_progress, rsa_public_key, \
                                                             paillier_public_key_n, self.signed_voters)


def _read_state():
    """
    Reads Election Board (EM) state from disk

    :return: an ElectionBoardState instance (read from disk)
    """
    with open("em.pickle", "rb") as f:
        state = pickle.load(f)
    return state


def _write_state(state):
    """
    Writes Election Board (EM) state to the disk

    :param state: the state to write to disk
    """
    with open("em.pickle", "wb") as f:
        pickle.dump(state, f)


if __name__ == "__main__":
    setup()
    kick_off()