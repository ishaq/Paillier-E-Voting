# Simple Voter
import Crypto
from Crypto import Random
from Crypto.Random import random

from paillier import *

import os, socket, sys

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
   e_vote = encrypt(pub_key, long(vote))
   
   
   # get vote signed by registrar
   
   # test
   print
   #print "You voted: " + vote
   #print "Encrypted: " + str(e_vote)
   
   server.send(str(e_vote))
   
   # Read in the acknowledgement
   print server.recv(1024)
   print
   server.close
   registrar.close()
   
if __name__ == "__main__":
   vote()
   
   
