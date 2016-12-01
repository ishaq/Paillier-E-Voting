"""
Configuration Settings
"""

'''Number of Candidates'''
NUM_CANDIDATES = 5

'''Number of Voters'''
NUM_VOTERS = 50

"""Election Board (EM) Host and Port"""
EM_ADDR = ("localhost", 9000)

"""Bulletin Board (BB) Host and Port"""
BB_ADDR = ("localhost", 9010)

"""Minimum Paillier Key Size"""
MIN_PAILLIER_KEY_SIZE = 128

'''Size of RSA Key'''
RSA_KEY_SIZE = 3072

"""Number of Times ZKP should be verified"""
ZKP_ITERATIONS = 1

"""Name of the file containing election results"""
ELECTION_RESULTS_FILENAME = "election_results.txt"

"""Name of the file containing bulletin board"""
BULLETIN_BOARD_FILENAME = "bulletin_board.txt"

