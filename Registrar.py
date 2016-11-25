# Registrar

import Crypto
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

import os, socket, sys


bs_size = 320
bvote_size = 128

# Run as server
# Initialize connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "0.0.0.0"
port = 1234 #hard coded in currently
   
sock.bind((host, port))
sock.listen(5)
print "registrar is open"

# Keep track of people who have voted already
voted = []
# Allowed to vote
voters = []

# Load in voters (hashes stored)
f = open('hashes.txt', 'r')
voters = f.read().split()

# Generate key for the blind signatures
priv = RSA.generate(1024)

# Run Loop for getting and verifying voter's vote
while True:
   # Connection from voter
   voter,addr = sock.accept()
   voter.send("Welcome to the Registrar's Office.")
   id = voter.recv(1024)
   
   # Generate key pair
   #priv = RSA.generate(4096) # Not sure whether to keep this in here or out of the while loop
   pub = priv.publickey()

   # Write public key to file
   f = open('regkey', 'w')
   f.write(pub.exportKey())
   f.close()

   # Hash id and check if matches any of the valid voters
   h = SHA256.new()
   h.update(id)
   check = h.hexdigest()
   
   # If matches up, then send verification
   if check in voters:
      print id + " is a registered voter."
      # Check if registered voter has voted already
      if check in voted:
         # uh oh
         # do something
         print "Already voted"
      else:
         voted.append(check)
      
         ####################################
         ######### Blind Signature ##########
         ####################################

         #bvote = voter.recv(bvote_size)
         bvote = voter.recv(10000) # change to above? for predetermined size
         
         # signed vote
         bs = str(priv.sign(bvote, 0)[0])

         # send back signed blinded vote
         # pad length of blinded signed vote to 320
         while (len(bs) < bs_size):
             bs += " "
         
         voter.send(bs)
         voter.close()

   else:
      print id + " is not a registered voter."
      # Do something   
      

