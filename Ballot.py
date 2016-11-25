# Ballot / Election Board

import Crypto
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import RSA
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
   port = 9876 # hard coded in currently
   
   sock.bind((host, port))
   sock.listen(5)
   print "Server running"
   
   # Buffer Size
   buff = 1024
   # Number of voters so far
   count = 0

   # Change the following to run indefinately and count when
   #  another counting authoring says so?
   total_voters = 3
   

   # Following section will probably be changed so the Counting Authority
   #  only has the secret key and decryption. So Ballot will write encrypted
   #   total to a file for the counting authority to read.

   # Retrieve secret key for decryption
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
      
      # Retrieve encrypted vote
      vote_data = voter.recv(voteSize)
      # Retrieve signed encyrpted vote
      signed_vote_data = voter.recv(4000) # change to predetermined size
      signed_vote_data = [long(signed_vote_data), None]
      
      # load bs public key
      f = open('regkey', 'r')
      reg_pub = RSA.importKey(f.read())
      f.close()
      
      # Verify signature
      assert reg_pub.verify(vote_data, signed_vote_data)
      # If true, continue, If false, close connection

      vote_data = vote_data.strip()
      vote = long(vote_data)
      
      ##################################
      ##### Zero Knowledge Proofs ######
      ##################################
      # Simpler version based of Discrete Log Problem
      # send challenge
      A = pub_key.n - 2
      e = long(getrandbits(64)) % A
      voter.send(str(e))
      # read in response (v,w)
      v = long(voter.recv(lenv).strip())
      w = long(voter.recv(lenw).strip())
      # verify!
      zkp_check = pow(vote, e, pub_key.n_sq)
      u = pow(w, e * pub_key.n, pub_key.n_sq) * v % pub_key.n_sq
      if (u == zkp_check):
          # If true, continue, if false, close connection
          print "YES"
      
      
      #################################
      ## Homomorphically Tally Votes ##
      #################################
      
      if count == 0:
         encrypted_votes = vote
      else:
         encrypted_votes = e_add(pub_key, encrypted_votes, vote)
      
      voter.send("Thank you for voting.")
      voter.close()
      count = count + 1
      
   
   # Move later to Counting Authority #
   decrypted = decrypt(sec_key, pub_key, encrypted_votes)
   print "Decrypted: " + str(decrypted)
   
if __name__ == "__main__":
   run_server()

   
      
      
      
      

      
      
      
      
