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

    @classmethod
    def from_dictionary(cls, params):
        enc_vote = int(params['enc_vote'], base=16)
        signed_enc_vote = int(params['signed_enc_vote'], base=16)
        return cls(enc_vote, signed_enc_vote)

    def to_dictionary(self):
        return {'enc_vote': hex(self.enc_vote),
                'signed_enc_vote': hex(self.signed_enc_vote)}


class RespZKPProvideCommitment:
    """
    response, requesting voter to provide ZKP commitment
    """
    def __repr__(self):
        return "<RespZKPProvideCommitment: Verifier requests the Prover to provide ZKP commitment.>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}


class ReqZKPChallenge:
    """
    request, requesting BB to provide ZKP challenge.

    this request contains the ZKP commitment
    """
    def __init__(self, a_params):
        self.a_params = a_params

    def __repr__(self):
        return "<ReqZKPChallenge: a_params: {}>".format(self.a_params)

    @classmethod
    def from_dictionary(cls, params):
        a_params_string = params['a_params']
        a_params = [int(a_params_string[i], base=16) for i in range(len(a_params_string))]
        return cls(a_params)

    def to_dictionary(self):
        a_params_strings = [hex(self.a_params[i]) for i in range(len(self.a_params))]
        return {'a_params': a_params_strings}


class RespZKPChallenge:
    """
    response, contains ZKP challenge
    """
    def __init__(self, e_s):
        self.e_s = e_s

    def __repr__(self):
        return "<RespZKPChallenge: e_s: {}>".format(self.e_s)

    @classmethod
    def from_dictionary(cls, params):
        e_s = int(params['e_s'], base=16)
        return cls(e_s)

    def to_dictionary(self):
        return {'e_s': hex(self.e_s)}


class ReqZKPVerify:
    """
    request containing ZKP that BB can verify
    """
    def __init__(self, e_params, z_params):
        self.e_params = e_params
        self.z_params = z_params

    def __repr__(self):
        return "<ReqZKPVerify: e_params: {}, z_params: {}>".format(self.e_params, self.z_params)

    @classmethod
    def from_dictionary(cls, params):
        e_params_string = params['e_params']
        z_params_string = params['z_params']
        e_params = [int(e_params_string[i], base=16) for i in range(len(e_params_string))]
        z_params = [int(z_params_string[i], base=16) for i in range(len(z_params_string))]
        return cls(e_params, z_params)

    def to_dictionary(self):
        e_params_strings = [hex(self.e_params[i]) for i in range(len(self.e_params))]
        z_params_strings = [hex(self.z_params[i]) for i in range(len(self.z_params))]
        return {'e_params': e_params_strings,
                'z_params': z_params_strings}


class RespCastVoteSuccess:
    """
    response indicating vote has been cast
    """
    def __init__(self, is_voting_complete = False):
        self.is_voting_complete = is_voting_complete

    def __repr__(self):
        return "<RespCastVoteSuccess: Vote has been casted successfully>"

    @classmethod
    def from_dictionary(cls, params):
        is_voting_complete = params['is_voting_complete']
        return cls(is_voting_complete)

    def to_dictionary(self):
        return {'is_voting_complete': self.is_voting_complete}


class RespVotingClosed:
    """
    response indicating voting session is closed
    """
    def __repr__(self):
        return "<RespVotingClosed: Voting process is now complete.>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}


class ReqCloseVoting:
    """
    request to closing voting session. It immediately closes voting session (if open) and
    sends the encrypted results to EM for decryption
    """
    def __repr__(self):
        return "<ReqCloseVoting: Request to close the voting process.>"

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}
