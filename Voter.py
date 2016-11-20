# Voter Class
##############
# Will "talk" with the registrar
# Will encrypt its own vote
# Will do the Zero Knowledge Proof with the Counter

import math
from Paillier import encrypt
from Crypto import Random
from Crypto.Random import random

class Voter:
    def __init__(self, iden):
        ''' 
        Initialize the voter.
        Arguments: ID
        Return Value: None

        Initialize the 'id' of the voter
        '''
        self.identity = iden

    def e_vote(self, vote):
        '''
        Use PaillierVote encrypt to encrypt vote.
        '''
        return encrypt(vote)
    
    def blind_sig(self, vote):
        pass
        
    def zkp(self, vote):
        pass


    def vote(self):
        pass

# The following will be changed to a method. 

# The identities will be kept by registrar.
if __name__  == '__main__':
    identities = []
    while True:
        # Keep track of voters
        iden = raw_input('What is your voter id? ')
        if iden in identities:
            print 'You have already voted!'
            print
            continue
        # Command to finish voting
        elif iden == 'exit':
            print
            break
        # Vote
        else:
            voter = Voter(iden)
            vote = raw_input('Vote: ')
            c = encrypt(vote)
            # Blind Sig
            # Send encrypted vote c to the ballot
            # Do zero knowledge proof
            identities.append(iden)
            print c
            print

