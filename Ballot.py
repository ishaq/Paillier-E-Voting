# Ballot / Election Board

import Crypto
from Crypto import Random
from Crypto.Random import random
from Crypto.Random.random import getrandbits

from paillier import *

import os, socket, sys
from os.path import isfile

voteSize = 128
lenv = 128
lenw = 128

# Run as server
# Initialize connection
def run_server():
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   host = "0.0.0.0"
   port = 9876 #hard coded in currently
   
   sock.bind((host, port))
   sock.listen(5)
   print "Server running"
   
   buff = 1024
   count = 0
   total_voters = 3
   
   f2 = open('secretkey.txt', 'r')
   data = f2.read().split()
   f2.close()
   sec_key = PrivateKey(3, 5, 9)
   sec_key.l = long(data[0])
   sec_key.m = long(data[1])
   
   f1 = open('publickey.txt', 'r')
   n = f1.read()
   f1.close() 
   pub_key = PublicKey(long(n))
   
   # Run Loop for getting and verifying voter's vote
   while count < total_voters:
      # Connection from voter
      voter,addr = sock.accept()
      
      vote_data = voter.recv(voteSize) # change to recieve vote and signed vote. Currently only recieving one vote
      vote_data = vote_data.strip()
      
      print vote_data
      vote = long(vote_data)
      
      #ZKP
      # send challenge
      # for fun, let's choose a large A
      A = pub_key.n - 2
      e = long(getrandbits(64)) % A
      # sent challenge
      voter.send(str(e))
      # read in v and w
      v = long(voter.recv(lenv).strip())
      w = long(voter.recv(lenw).strip())

      # verify!
      zkp_check = pow(vote, e, pub_key.n_sq)
      u = pow(w, e * pub_key.n, pub_key.n_sq) * v % pub_key.n_sq
      print u
      print zkp_check
      if (u == zkp_check):
         print "YES"
      # if yes, do the following. if not, skip to after the count and send a invalid vote to voter and close.
      
      # add up votes
      if count == 0:
         encrypted_votes = vote
      else:
         encrypted_votes = e_add(pub_key, encrypted_votes, vote)
      
      voter.send("Thank you for voting.")
      voter.close()
      
      count = count + 1
      ##
   
   decrypted = decrypt(sec_key, pub_key, encrypted_votes)
   
   print "Decrypted: " + str(decrypted)
   
if __name__ == "__main__":
   run_server()

   
      
      
      
      
