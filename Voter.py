# Voter
import Crypto
from Crypto import Random
from Crypto.Random import random
from Crypto.Random.random import getrandbits
import fractions

from paillier import *

import os, socket, sys

voteSize = 128
lenv = 128
lenw = 128

def vote():
   host = "0.0.0.0"
   reg_port = 1234
   serv_port = 9876

   # speak with the registrar first
   registrar = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   registrar.connect((host, reg_port))
   print registrar.recv(1024)
   id = raw_input("Name: ")
   registrar.send(str(id))
   # Recieve a key to vote?
   
   
   # speak with ballot
   server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   server.connect((host, serv_port))
   
   # Send key to vote?
   vote = raw_input("Your vote: ")
   #encrypted_vote = encrypt(vote)
   # public key is 
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
   # ballot will need to unpad

   server.send(s_vote) # send padded vote
   
   # ZKP (one iteration)
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
   
   
   # Read in the acknowledgement
   print server.recv(1024)
   print
   server.close
   registrar.close()
   
if __name__ == "__main__":
   vote()
   
   
