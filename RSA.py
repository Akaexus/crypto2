import typing as t
from random import randint
from math import gcd
from functools import partial




class Keychain(t.TypedDict):
    e: int | None
    n: int
    d: int|None

class RSA(t.NamedTuple):
    encrypt:t.Callable[[str],list[int]]
    decrypt:t.Callable[[list[int]],str]
    keys:Keychain

def hexdump(xs):
    return ' '.join(f'{x:08X}' for x in xs)

def cipher(message:bytes,key:t.Tuple[int,int]):
    p, n = key
    return [pow(x, p, n) for x in message]


def isprime(n:int):
    if n == 2: return True
    if n % 2 == 0: return False
    return all(n % i != 0 for i in range(3, int(n**0.5)+1, 2))

def randuntil(lb:int, ub:int, until:t.Callable[[int],bool]):
    x = randint(lb, ub)
    
    while not until(x):
        x = randint(lb, ub)
        
    return x 

def keygen(p:int|None=None, q:int|None=None)->Keychain:
    p = p or randuntil(2, 10**4, isprime);      
    q = q or randuntil(2, 10**4, lambda x: isprime(x) and x!=p);      
    assert p != q,f"Podano/wylosowano 2 razy {p}"
    n = p*q;                                                          
    phi = (p - 1)*(q - 1);                                              
    e = randuntil(3, 2**32, lambda x: gcd(x, phi) == 1); 
    d = pow(e,-1,phi)
    return {'e':e,'n':n,'d':d}

def extract_keys(t:Keychain,keys_list:list[str]):
    return (t.get(key) for key in keys_list)







def give_me_ciphering(keys=keygen())->RSA:
    encrypt = partial(lambda m,k: cipher(bytes(m, 'utf-8'),k ), k=extract_keys(keys,['e','n']))
    decrypt = partial(lambda m,k: bytes(cipher(m,k)).decode('utf-8'), k=extract_keys(keys,['d','n']))
    encrypt = t.cast(t.Callable[[str],list[int]], encrypt) #type:ignore
    decrypt = t.cast(t.Callable[[list[int]],str], decrypt) #type:ignore
    return RSA(encrypt, decrypt,keys)

# rsa  = give_me_ciphering()
# initial = "hello world"
# encrypted = rsa.encrypt(initial)
# decrypted = rsa.decrypt(encrypted)
# print(f"Initial: {initial}")
# print(f"Encrypted: {hexdump(encrypted)}")
# print(f"Decrypted: {decrypted}")