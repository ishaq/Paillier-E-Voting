# CSCI-6230 Project (Fall 2016)
This codebase is a proof of concept (PoC) of an e-voting system using Paillier homomorphic encryption.

## Setup
The project was written using Python 3.5.2. To install dependencies (PyCrypto, etc), change to root project directory (the one containing _requirements.txt_) and run:

```bash
pip install -r requirements.txt
```

## Assumptions
* Voter, Bulletin Board (BB) and Election Board (EM) systems are secure (i.e. adversary cannot access them and/or obtain keys)
* Connection between Voter, Bulletin Board (BB) and Election Board (EM) is secure and trusted. (i.e. no MITM attack)
* Any vulnerability in PyCrypto is out of scope
* Any vulnerability in Paillier encryption library used by the project is out of scope

## Authors
* Muhammad Ishaq (ishaqm@rpi.edu)
* Daniel Park (parkd5@rpi.edu)