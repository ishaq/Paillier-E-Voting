# Paillier Encryption and Decryption
# Tallying Votes
import math
from Crypto import Random
from Crypto.Random import random

# The parameters of encryption will be given.
#  So they are currently hardcoded


# Methods used in encryption/decryption

# Add up all the votes
def count( c ):
	count = 1
	for i in range (0, len(c)):
		count = count * c[i] % (126869 * 126869)
	return count

def lcm( x, y ):
    if x > y:
        greater = x
    else:
        greater = y

    while( True ):
        if( ( greater % x == 0 ) and ( greater % y == 0 ) ):
            lcm = greater
            break
        greater += 1

    return lcm

# Encryption
def encrypt(m):
    # Primes p, q
    p = 293
    q = 433
    # Public key
    n = p * q # 35
    g = 6497955158 # Should be given
    # Random number from PRNG
    r_gen = Random.new()
    r = r_gen.read( n ).encode( 'hex' )
    r = int( r, 16 ) % n
    # print str(r)

    # Begin Encryption
    print "Hi, I chose to vote: " + str( int( m, 10 ) )
    c = ( pow( g, int ( m, 10 ) ) * pow( r, n ) ) % ( n * n )
    return c

# L function
def L(u):
    n = 126869 #given
    l = (u - 1)/n
    return l

# Decryption method
def decrypt( c ):
    p = 293 #given
    q = 433 #given
    n = p * q # 126869
    g = 6497955158 #given
    u = pow( L( pow( g, lcm( p - 1, q - 1 ) ) % ( n * n ) ), -1 ) % n
    m = ( ( L( ( pow( c, lcm( p - 1 , q - 1 ) ) ) % ( n * n ) ) ) * u ) % n
    #
    # If more than two candidates... Use a knapsack-like counting method
    # Where 10^0 is a vote for C1, 10^2 is a vote for C2, etc...
    return m

# Main
def main():
    ctxts = []

    # Test
    # Begin Random Voting
    for i in range (0, 5):
        print "Iteration: m = " + str(i)
        c = encrypt(random.choice(['0', '1']))
        print "Ciphertext: " + str(c)
        print ""
        ctxts.append(c)
    print

    while True:
        response = raw_input('Vote: ')
        if response == 'exit':
            break
        response = encrypt(response)
        print "Ciphertext: " + str(response)
        print ""
        ctxts.append(response)

    # Tally Votes without Decryption
    print "The Cryptographic Tally of Votes: " + str(count(ctxts))

    # Decryption of the sum to get the winner.
    print "The Decryption of the Tally: " +  str(decrypt(count(ctxts))% 126869 )

main()
