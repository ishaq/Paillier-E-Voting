# Voter
import Crypto
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import random
from Crypto.Random.random import getrandbits
import fractions

from paillier import *

import os, socket, sys

signed_size = 320
voteSize = 128
lenv = 128
lenw = 128

def vote():
   host = "0.0.0.0"
   reg_port = 1234
   serv_port = 9876

   #############################
   ###### Identification #######
   #############################

   registrar = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   registrar.connect((host, reg_port))
   print registrar.recv(1024)
   id = raw_input("Name: ")
   registrar.send(str(id))
   # Recieve a key to vote?


   #############################
   ########## Voting ###########
   #############################

   # speak with ballot
   server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   server.connect((host, serv_port))
   
   # Send key to vote?
   vote = raw_input("Your vote: ")
   # Retrieve public key 
   f1 = open('publickey.txt', 'r')
   n = f1.read()
   f1.close() 
   pub_key = PublicKey(long(n))
   x = get_x(pub_key)
   e_vote = encrypt(pub_key, x, long(vote)) 
   # pad the vote
   s_vote = str(e_vote)
   while (len(s_vote) < voteSize):
      s_vote += " "

   ##############################
   ###### Blind Signature #######
   ##############################
   f = open('regkey', 'r')
   reg_pub = RSA.importKey(f.read())
   f.close()
   # generate random bits
   k  = random.randint(reg_pub.n >> 100, reg_pub.n)
   # blind the vote
   bvote = reg_pub.blind(s_vote, k)

   # get blinded vote signed by registrar
   registrar.send(bvote)

   # recieve and unpad signed and unblind
   bsigned_vote = registrar.recv(100000).strip() # change to predef size
   signed_vote = reg_pub.unblind(long(bsigned_vote), k)
   ddd = reg_pub.verify(s_vote, (signed_vote,))

   # send to ballot 
   server.send(s_vote) # send padded vote
   server.send(str(signed_vote)) # send padded signed vote
   


   ##############################
   #### Zero Knowledge Proof ####
   ##############################

   # ZKP (one iteration) Relies on discrete log problem
   # receive challenge
   e = long(server.recv(1024))
   a1 = pow(pub_key.g, e * long(vote), pub_key.n_sq)
   a2 = x
   
   #pad v and w
   v = str(a1)
   while (len(v) < lenv):
      v += " "
   w = str(a2)
   while (len(w) < lenw):
      w += " "
   
   server.send(v);
   server.send(w);
   
   

   ###############################
   ############ DONE #############
   ###############################

   # Read in the acknowledgement
   print server.recv(1024)
   print
   server.close
   registrar.close()
   
if __name__ == "__main__":
   vote()
   
   
