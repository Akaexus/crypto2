import math
import random
from colorama import init, Fore, Back, Style


def bobprint(string):
    print(f'{Fore.BLUE}[BOB]: {string}{Style.RESET_ALL}')


def aliceprint(string):
    print(f'{Fore.RED}[ALICE]: {string}{Style.RESET_ALL}')

def compareprint(what, alice_value, bob_value):
    print(f'{what}\t{Fore.RED}{alice_value}\t{Fore.BLUE}{bob_value}{Style.RESET_ALL}')

def is_prime(num):
    if num < 2:
        return True
    for i in range(2, math.ceil(num**0.5)):
        if num % i == 0:
            return False
    return num > 1


def find_primes():
    primes = []
    for i in range(1000, 10000):
        if is_prime(i):
            primes.append(i)
    return primes


def mod_pow(a, b, m):
    a %= m
    p = 1
    for i in range(0, b):
        p *= a
        p %= m
    return p


def find_factors(num):
    l = []
    for i in range(2, math.ceil(num ** .5)):
        while num % i == 0:
            l.append(i)
            num /= i
    if num > 2:
        l.append(num)
    return l

def find_prim_root(num):
    phi = num - 1
    factors = find_factors(phi)
    # print(factors)
    primitive = None
    for i in range(2, phi + 1):
        flag = False
        for factor in factors:
            if mod_pow(i, int(phi / factor), num) == 1:
                flag = True
                break
        if not flag:
            primitive = i
    return primitive


N = int(input('N> '))
if not is_prime(N):
    print('N is not prime')
    exit(1)

G = find_prim_root(N)

compareprint('         ', 'Alice', 'Bob')

alice_private_key = math.floor(N / 2) + 1  # x
# aliceprint(f'alice_private_key {alice_private_key}')
bob_private_key = math.floor(N / 3) + 1  # y
# bobprint(f'bob_private_key {bob_private_key}')
compareprint('Private key', alice_private_key, bob_private_key)

alice_public_key = mod_pow(G, alice_private_key, N)  # X
# aliceprint(f'alice_public_key {alice_public_key}')
bob_public_key = mod_pow(G, bob_private_key, N)  # Y
# bobprint(f'bob_public_key {bob_public_key}')
compareprint('Public key', alice_public_key, bob_public_key)


alice_tmp_private_key = random.randint(0, 1000)
# aliceprint(f'alice_tmp_private_key {alice_tmp_private_key}')
bob_tmp_private_key = random.randint(0, 1000)
# bobprint(f'bob_tmp_private_key {bob_tmp_private_key}')
compareprint('Tmp private key', alice_tmp_private_key, bob_tmp_private_key)

alice_tmp_public_key = mod_pow(G, alice_tmp_private_key, N)  # A
# aliceprint(f'alice_tmp_public_key {alice_tmp_public_key}')
bob_tmp_public_key = mod_pow(G, bob_tmp_private_key, N)  # B
# bobprint(f'bob_tmp_public_key {bob_tmp_public_key}')

compareprint('Tmp public key', alice_tmp_public_key, bob_tmp_public_key)

alice_shared_key = mod_pow(
    bob_tmp_public_key * mod_pow(bob_public_key, bob_tmp_public_key, N),
    alice_private_key * alice_tmp_public_key + alice_tmp_private_key,
    N
)

bob_shared_key = mod_pow(
    alice_tmp_public_key * mod_pow(alice_public_key, alice_tmp_public_key, N),
    bob_private_key * bob_tmp_public_key + bob_tmp_private_key,
    N
)

compareprint('Shared keys', alice_shared_key, bob_shared_key)