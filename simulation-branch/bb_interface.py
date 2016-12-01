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

    def __repr__(self):
        return "<ReqCastVote: enc_vote: {}, signed_enc_vote: {}>".format(self.enc_vote, self.signed_enc_vote)


class RespZKPProvideCommitment:
    """
    response, requesting voter to provide ZKP commitment
    """
    def __repr__(self):
        return "<RespZKPProvideCommitment: Verifier requests the Prover to provide ZKP commitment.>"


class ReqZKPChallenge:
    """
    request, requesting BB to provide ZKP challenge.

    this request contains the ZKP commitment
    """
    def __init__(self, a_params):
        self.a_params = a_params

    def __repr__(self):
        return "<ReqZKPChallenge: a_params: {}>".format(self.a_params)


class RespZKPChallenge:
    """
    response, contains ZKP challenge
    """
    def __init__(self, e_s):
        self.e_s = e_s

    def __repr__(self):
        return "<RespZKPChallenge: e_s: {}>".format(self.e_s)


class ReqZKPVerify:
    """
    request containing ZKP that BB can verify
    """
    def __init__(self, e_params, z_params):
        self.e_params = e_params
        self.z_params = z_params

    def __repr__(self):
        return "<ReqZKPVerify: e_params: {}, z_params: {}>".format(self.e_params, self.z_params)


class RespCastVoteSuccess:
    """
    response indicating vote has been cast
    """
    def __init__(self, is_voting_complete = False):
        self.is_voting_complete = is_voting_complete

    def __repr__(self):
        return "<RespCastVoteSuccess: Vote has been casted successfully>"


class RespVotingClosed:
    """
    response indicating voting session is closed
    """
    def __repr__(self):
        return "<RespVotingClosed: Voting process is now complete.>"


class ReqCloseVoting:
    """
    request to closing voting session. It immediately closes voting session (if open) and
    sends the encrypted results to EM for decryption
    """
    def __repr__(self):
        return "<ReqCloseVoting: Request to close the voting process.>"
