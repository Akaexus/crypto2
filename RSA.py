import typing as t
from random import randint
from math import gcd
from functools import partial


class Keychain(t.TypedDict):
    e: int
    n: int
    d: int
class PublicKeychain(t.TypedDict):
    e: int
    n: int

class PrivateKeychain(t.TypedDict):
    d: int
    n: int

class RSA(t.NamedTuple):
    encrypt:t.Callable[[int],int]
    decrypt:t.Callable[[int],int]
    keys:Keychain


def cipher(message:int,key:t.Tuple[int,int]):
    p, n = key
    return pow(message, p, n)


def isprime(n:int):
    if n == 2: return True
    if n % 2 == 0: return False
    return all(n % i != 0 for i in range(3, int(n**0.5)+1, 2))

def randuntil(lb:int, ub:int, until:t.Callable[[int],bool]):
    x = randint(lb, ub)
    
    while not until(x):
        x = randint(lb, ub)
        
    return x 

def keygen(p:int|None = None, q:int|None = None)->Keychain:
    p = p or randuntil(2, 10**4, isprime);      
    q = q or randuntil(2, 10**4, lambda x: isprime(x) and x!=p);      
    assert p != q,f"Podano/wylosowano 2 razy {p}"
    n = p*q;                                                          
    phi = (p - 1)*(q - 1);                                              
    e = randuntil(3, 2**32, lambda x: gcd(x, phi) == 1); 
    d = pow(e,-1,phi)
    return {'e':e,'n':n,'d':d}

def extract_keys(t:Keychain,keys_list:list[str])->t.Tuple[int,int]:
    return tuple(t.get(key) for key in keys_list) #type:ignore



def give_me_ciphering(keys=keygen())->RSA:
    print(keys)
    encrypt = partial(cipher, key=extract_keys(keys,['e','n']))
    decrypt = partial(cipher, key=extract_keys(keys,['d','n']))
    encrypt = t.cast(t.Callable[[int],int], encrypt) #type:ignore
    decrypt = t.cast(t.Callable[[int],int], decrypt) #type:ignore
    return RSA(encrypt, decrypt,keys)

# rsa  = give_me_ciphering()
# initial = 2137
# encrypted = rsa.encrypt(initial)
# decrypted = rsa.decrypt(encrypted)
# print(f"Initial: {initial}")
# print(encrypted)
# print(f"Decrypted: {decrypted}")