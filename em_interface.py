"""
Contains request and response objects for Election Board (EM)
"""

from Crypto.PublicKey import RSA
from paillier import paillier


class ReqPublicKeys:
    """
    request for public keys
    """

    @classmethod
    def from_dictionary(cls, params):
        return cls()

    def to_dictionary(self):
        return {}

class RespPublicKeys:
    """
    response contain public keys
    """
    def __init__(self, rsa_pub_key, paillier_pub_key):
        self.rsa_pub_key = rsa_pub_key
        self.paillier_pub_key = paillier_pub_key

    @classmethod
    def from_dictionary(cls, params):
        rsa_pub_key = RSA.importKey(params['rsa_pub_key'].encode('ascii'))
        paillier_pub_key = paillier.PublicKey.from_n(int(params['paillier_pub_key'], base=16))
        return cls(rsa_pub_key, paillier_pub_key)

    def to_dictionary(self):
        rsa_pub_key_exported = self.rsa_pub_key.exportKey().decode('ascii')
        paillier_pub_key_str = hex(self.paillier_pub_key.n)
        return {'rsa_pub_key': rsa_pub_key_exported, 'paillier_pub_key': paillier_pub_key_str}

class ReqBlindSign:
    """
    request for blind signature
    """
    def __init__(self, voter_id, voter_pin, blinded_encrypted_vote):
        self.voter_id = voter_id
        self.voter_pin = voter_pin
        self.blinded_encrypted_vote = blinded_encrypted_vote

    @classmethod
    def from_dictionary(cls, params):
        voter_id = params['voter_id']
        voter_pin = params['voter_pin']
        blinded_encrypted_vote = int(params['blinded_encrypted_vote'], base=16)
        return cls(voter_id, voter_pin, blinded_encrypted_vote)

    def to_dictionary(self):
        blinded_encrypted_vote_packed = hex(self.blinded_encrypted_vote)
        return {'voter_id': self.voter_id,
                'voter_pin': self.voter_pin,
                'blinded_encrypted_vote': blinded_encrypted_vote_packed}

class RespBlindSign:
    """
    response containing blind signature
    """
    def __init__(self, signed_blinded_encrypted_vote):
        self.signed_blinded_encrypted_vote = signed_blinded_encrypted_vote

    @classmethod
    def from_dictionary(cls, params):
        signed_blinded_encrypted_vote = int(params['signed_blind_encrypted_vote'], base=16)
        return cls(signed_blinded_encrypted_vote)

    def to_dictionary(self):
        return {'signed_blind_encrypted_vote': hex(self.signed_blinded_encrypted_vote)}



class ReqDisplayResults:
    """
    request to display results (it immediately closes voting and decrypts the results)
    """
    def __init__(self, encrypted_results):
        self.encrypted_results = encrypted_results

    @classmethod
    def from_dictionary(cls, params):
        encrypted_results = int(params['encrypted_results'], base=16)
        return cls(encrypted_results)

    def to_dictionary(self):
        return {'encrypted_results': hex(self.encrypted_results)}
