"""
Contains request and response objects for Bulletin Board (BB)
"""


class ReqCastVote:
    """
    request to cast vote
    """
    def __init__(self, enc_vote, signed_enc_vote):
        self.enc_vote = enc_vote
        self.signed_enc_vote = signed_enc_vote


class RespProvideZKP:
    """
    response, requesting voter to provide ZKP
    """
    # TODO: fill it in
    pass


class ReqVerifyZKP:
    """
    request containing ZKP that BB can verify
    """
    # TODO: fill it in
    pass


class RespCastVoteSuccess:
    """
    response indicating vote has been cast
    """
    pass


class RespVotingClosed:
    """
    response indicating voting session is closed
    """
    pass


class ReqCloseVoting:
    """
    request to closing voting session. It immediately closes voting session (if open) and
    sends the encrypted results to EM for decryption
    """
    pass
