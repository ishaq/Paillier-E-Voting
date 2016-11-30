# CSCI-6230 Project (Fall 2016)
This codebase is a proof of concept (PoC) of an e-voting system using Paillier homomorphic encryption.

## Setup
The project was written using Python 3.5.2. To install dependencies (PyCrypto, etc), change to root project directory (the one containing _requirements.txt_) and run:

```bash
pip install -r requirements.txt
```

### How to Run

**Note:** You can modify the number of candidates and number of voters in `config.py` 

1. Run cleanup script (to clean stale state files)

    ```bash
    python cleanup.py
    ```
2. Run Election Board (EM), Bulletin Board (BB) and Voter in that order.

    ```bash
    # in Terminal 1 (Election Board - EM)
    python em.py
    ```
    
    ```bash
    # in Terminal 2 (Bulletin Board - BB)
    python bb.py
    ```
    
    ```bash
    # in Terminal 3 (Voter)
    python voter.py
    ```
    
3. Voting will stop automatically when all voters have cast their vote. It can also be manually stopped by running `close_voting.py`

    ```bash
    python close_voting.py
    ```
    
Voter IDs are of the pattern `Voter00`, `Voter01`, `Voter02`, etc. Voter's PIN is the same as his ID i.e. PIN for `Voter00` is `Voter00` and so on.

## Assumptions
1. Keys are shared between Election Board (EM) and Bulletin Board (BB) in advance. Key sharing is secure and trusted.
1. Bulletin Board (BB) and Election Board (EM) systems are secure (i.e. adversary cannot control them and/or obtain keys).
1. Election Board (EM) is, in reality, a group of individuals/institutions who possess secret key in t-n threshold sharing fashion. They decrypt their share of the final encrypted tally (they never physically come together) .
1. Any vulnerability in PyCrypto is out of scope

## Authors
* Muhammad Ishaq (ishaq@ishaq.pk)
* Daniel Park (parkd5@rpi.edu)

## Credits
* [PyCrypto](https://pypi.python.org/pypi/pycrypto) is used for RSA encryption and SHA-256 hashes
* [Paillier](https://github.com/mikeivanov/paillier) is used for Paillier homomorphic encryption. We modified it a considerably to fix bugs and make it work with Python 3.