"""
Contains request and response objects for Election Board (EM)
"""

class ReqPublicKeys:
    """
    request for public keys
    """
    pass

class RespPublicKeys:
    """
    response contain public keys
    """
    def __init__(self, rsa_pub_key, paillier_pub_key):
        self.rsa_pub_key = rsa_pub_key
        self.paillier_pub_key = paillier_pub_key

class ReqBlindSign:
    """
    request for blind signature
    """
    def __init__(self, voter_id, voter_pin, blinded_encrypted_vote):
        self.voter_id = voter_id
        self.voter_pin = voter_pin
        self.blinded_ecnrypted_vote = blinded_encrypted_vote

class RespBlindSign:
    """
    response containing blind signature
    """
    def __init__(self, signed_blinded_encrypted_vote):
        self.signed_blinded_encrypted_vote = signed_blinded_encrypted_vote


class ReqDisplayResults:
    """
    request to display results (it immediately closes voting and decrypts the results)
    """
    def __init__(self, encrypted_results):
        self.encrypted_results = encrypted_results
