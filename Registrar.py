# Registrar

import Crypto
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

import os, socket, sys

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

# Run Loop for getting and verifying voter's vote
while True:
   # Connection from voter
   voter,addr = sock.accept()
   voter.send("Welcome to the Registrar's Office.")
   id = voter.recv(1024)
   
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
         print "Already voted"
      else:
         voted.append(check)
      
         ####################################
         ######### Blind Signature ##########
         ####################################
   else:
      print id + "is not a registered voter."
         
      
   
