# Ballot / Election Board

import Crypto
from Crypto import Random
from Crypto.Random import random

from paillier import *

import os, socket, sys
from os.path import isfile

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
      
      vote_data = voter.recv(buff) # change to recieve vote and signed vote. Currently only recieving one vote
      print vote_data
      vote = long(vote_data)
      
      # add up votes
      if count == 0:
         encrypted_votes = vote
      else:
         encrypted_votes = e_add(pub_key, encrypted_votes, vote)
      
      voter.send("Thank you for voting.")
      voter.close()
      
      count = count + 1
      
   
   decrypted = decrypt(sec_key, pub_key, encrypted_votes)
   
   print "Decrypted: " + str(decrypted)
   
if __name__ == "__main__":
   run_server()
   
      
      
      
      
