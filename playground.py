from Crypto.Random import random
from paillier import paillier

def do_paillier_voting_simulation(candidates_count, voters_count):
    if not (voters_count > candidates_count):
        raise ValueError("voters_count needs to be greater than candidates_count")

    plain_candidates_votes = [0] * candidates_count

    # 1. Generate Key (this is done at EM)
    bits_per_candidate = voters_count.bit_length()
    # at least 16 bits for the key
    key_size = 16 if (candidates_count * bits_per_candidate) < 16 else (candidates_count * bits_per_candidate)
    print("key_size: {}, ({} bits per candidate)".format(key_size, bits_per_candidate))
    sk, pk = paillier.generate_keypair(key_size)


    # 2. Generate Initial Sum (this is done at BB, it has the pk of EM)
    initial_count = 0
    c = paillier.encrypt(pk, initial_count)
    d = paillier.decrypt(sk, pk, c)
    print("c: {}, d: {}".format(c, d))

    # 3. Voting is done
    for i in range(voters_count):
        r = random.randint(0, candidates_count-1)
        print("{}: Voting for candidate: {}".format(i, r))
        plain_candidates_votes[r] += 1
        # Generate encryption of the vote
        vote = 1 << (r * bits_per_candidate)
        encrypted_vote = paillier.encrypt(pk, vote)
        c = paillier.e_add(pk, c, encrypted_vote)
        # print("vote: {:b}, encrypted_vote: {}, c: {}".format(vote, encrypted_vote, c))
        # (then try generating an encryption with a different key)

    # 4. Final results sent to EM (EM can decrypt since it has both pk and sk)
    d = paillier.decrypt(sk, pk, c)
    print("Final Results")
    print("c: {}, d:{} ({:b})".format(c, d, d))
    candidates_votes = [0] * candidates_count
    mask = pow(2, bits_per_candidate) - 1
    for i in range(candidates_count):
        votes_count = (d >> (i * bits_per_candidate)) & mask
        print("{}, mask: {:b}, d: {:b}, votes: {}".format(i, mask, d, votes_count))
        candidates_votes[i] = votes_count

    print("DecryptedVotes: {}".format(candidates_votes))
    print("Plain Votes : {}".format(plain_candidates_votes))
    print("Paillier Voting calculated correct vote counts? {}".format(candidates_votes == plain_candidates_votes))
    if not candidates_votes == plain_candidates_votes:
        raise ArithmeticError("Paillier Voting Failed. Did not calculate correct vote counts")



if __name__ == '__main__':
    # The project requirement was at least 5 candidates.
    do_paillier_voting_simulation(10, 100)
