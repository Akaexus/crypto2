from dataclasses import dataclass
import typing as t
from RSA import Keychain,PublicKeychain,PrivateKeychain

@dataclass
class Milionaire:
    name:str
    cash_amount: int
    ciphered_cash_amount:list[int]|None
    keys_owned:Keychain | PublicKeychain | PrivateKeychain 
    

