# Credits to
# mikeivanov
# https://github.com/mikeivanov/paillier/

import math
from . import primes

def egcd(a, b):
    """
    Euclidean Extendted Algorithm for GCD

    Code based on: https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """The multiplicitive inverse of a in the integers modulo p:
             a * b == 1 mod p
           Returns b.
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

class PrivateKey(object):

    def __init__(self, p, q, n):
        self.l = (p-1) * (q-1)
        self.m = modinv(self.l, n)
        self.p = p
        self.q = q

    def __repr__(self):
        return '<PrivateKey: %s %s %s %s>' % (self.p, self.q, self.l, self.m)

class PublicKey(object):

    @classmethod
    def from_n(cls, n):
        return cls(n)

    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1

    def __repr__(self):
        return '<PublicKey: %s %s %s>' % (self.n, self.g, self.n_sq)

def generate_keypair(bits):
    p = primes.generate_prime(bits / 2)
    q = primes.generate_prime(bits / 2)
    n = p * q
    return PrivateKey(p, q, n), PublicKey(n)

def encrypt(pub, plain):
    r = get_r_in_z_n_star(pub)
    return encrypt_with_r(pub, r, plain)

def get_r_in_z_n_star(pub):
    while True:
        r = primes.generate_prime(int(round(math.log(pub.n, 2))))
        # r is in $$Z_{n}^{*}$$ i.e. Z-n-star (it has to be have a multiplicative inverse in Zn)
        if r > 0 and r < pub.n and math.gcd(pub.n, r) == 1:
            break
    return r

def encrypt_with_r(pub, r, plain):
    x = pow(r, pub.n, pub.n_sq)
    cipher = (pow(pub.g, plain, pub.n_sq) * x) % pub.n_sq
    return cipher

def e_add(pub, a, b):
    """Add one encrypted integer to another"""
    return a * b % pub.n_sq

def e_add_const(pub, a, n):
    """Add constant n to an encrypted integer"""
    return a * pow(pub.g, n, pub.n_sq) % pub.n_sq

def e_mul_const(pub, a, n):
    """Multiplies an ancrypted integer by a constant"""
    return pow(a, n, pub.n_sq)

def decrypt(priv, pub, cipher):
    x = pow(cipher, priv.l, pub.n_sq) - 1
    plain = ((x // pub.n) * priv.m) % pub.n
    return plain
