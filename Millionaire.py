from dataclasses import dataclass
import typing as t
from RSA import Keychain

@dataclass
class Milionaire:
    name:str
    cash_amount: int
    keys_owned:Keychain
    

