"""
Bulletin Board (BB)

This module uses paillier's homomorphic properties to keep track of vote sums. It also performs ZKP to make sure user
knows his vote.
"""


import socket
import pickle

from Crypto.Hash import SHA256
from paillier import paillier

import common
import config
from bb_interface import *
import em_interface

def setup():
    """
    Setups up the server
    """

    try:
        state = _read_state()
        print("Existing State found, loading it: {}".format(state))
    except FileNotFoundError:
        print("No previous state found, creating one")
        state = BulletinBoardState()
        _write_state(state)

    print("Bulletin Board (BB) setup complete...")


def kick_off():
    """
    Kicks off the server

    creates/binds a socket and starts listening for requests
    """

    # Get the keys
    pub_keys = common.get_public_key_from_em()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(config.BB_ADDR)
    sock.listen()

    # Read the state
    state = _read_state()

    # Create initial sum if needed
    if state.encrypted_sums is None:
        # Prepare initial sum
        state.encrypted_sums = paillier.encrypt(pub_keys.paillier_pub_key, 0)
        _write_state(state)

    print("Bulletin Board (BB) started ...")

    # Message Processing Loop
    while True:
        conn, addr = sock.accept()
        msg = common.read_message(conn)
        if not msg:
            # The client has sent an invalid message, we close the connection
            # NOTE: We could also transmit an explanatory message to the client here
            conn.close()
            continue
        _handle_message(msg, conn, state, pub_keys)
        conn.close()
        _write_state(state)


def shutdown():
    """
    Shuts down the server

    stops listening and shuts down sockets
    """

# --- Private ---

def _handle_message(msg, conn, state, pub_keys):
    """
    Handles the message as appropriate

    :param msg: message from the client socket
    :param conn: the client socket
    :param state: bulletin board state
    :return:
    """

    print("Received Message is: {}".format(msg))
    if isinstance(msg, ReqCastVote):
        _handleReqCastVote(msg, conn, state, pub_keys)
    elif isinstance(msg, ReqCloseVoting):
        _handleReqCloseVoting(msg, conn, state, pub_keys)
    pass

def _handleReqCastVote(msg, conn, state, pub_keys):
    # is voting open?
    if not state.voting_in_progress:
        common.write_message(conn, common.RespError("Voting is NOT open"))
        return

    # check ZKP
    if not _handleZKP(msg, conn, state):
        common.write_message(conn, common.RespError("Zero Knowledge Proof failed, cannot cast vote"))
        return

    # check signature
    if not pub_keys.rsa_pub_key.verify(msg.enc_vote, (msg.signed_enc_vote, )):
        common.write_message(conn, common.RespError("Signature verification failed"))
        return

    # check that user hasn't already voted
    sha256 = SHA256.new()
    sha256.update(str(msg.signed_enc_vote).encode("utf-8"))
    vote_hash = sha256.digest()
    if vote_hash in state.counted_vote_hashes.keys():
        common.write_message(conn, common.RespError("Already counted this vote"))
        return

    # all checks passed, cast the vote
    state.encrypted_sums = paillier.e_add(pub_keys.paillier_pub_key, state.encrypted_sums, msg.enc_vote)
    state.counted_vote_hashes[vote_hash] = True

    if len(state.counted_vote_hashes.keys()) == config.NUM_VOTERS:
        print("All voters have voted.")
        _handleReqCloseVoting(msg, conn, state)

        resp = RespVotingClosed()
        common.write_message(conn, resp)
    else:
        resp = RespCastVoteSuccess()
        common.write_message(conn, resp)



def _handleReqCloseVoting(msg, conn, state):
    state.voting_in_progress = False
    sock_to_em = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_to_em.connect(config.EM_ADDR)
    req = em_interface.ReqDisplayResults(state.encrypted_sums)
    common.write_message(sock_to_em, req)
    # the socket will be closed by EM


def _handleZKP(msg, conn, state):
    # TODO: ZKP loop to make sure user knows his vote
    return True


class BulletinBoardState():
    """
    A model to encapsulate Bulletin Board (BB) state
    """
    def __init__(self):
        self.voting_in_progress = True
        self.counted_vote_hashes = {}
        self.encrypted_sums = None

    def __str__(self):
        return "<BulletinBoardState: {}, {}, {}>".format(self.voting_in_progress, self.counted_vote_hashes, \
                                                         self.encrypted_sums)


def _read_state():
    """
    Reads Bulletin Board (BB) state from disk

    :return: an BulletinBoardState instance (read from disk)
    """
    with open("bb.pickle", "rb") as f:
        state = pickle.load(f)
    return state


def _write_state(state):
    """
    Writes Bulletin Board (BB) state to the disk

    :param state: the state to write to disk
    """
    with open("bb.pickle", "wb") as f:
        pickle.dump(state, f)


if __name__ == "__main__":
    setup()
    kick_off()