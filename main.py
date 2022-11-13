from Millionaire import Milionaire
import RSA
import random
from math import gcd

MAX_CASH = 100000
#apolonia generuje klucze
def milionaires_problem(bogus_money:int,apolonia_money = 0)->bool:
    keys = RSA.keygen()
    ciphering = RSA.give_me_ciphering(keys)

    Apolinia = Milionaire("Apolinia", apolonia_money,None, RSA.PrivateKeychain(d=keys['d'],n=keys['n']))

    #apolonia przesyla klucz publiczny
    Bogus = Milionaire("Bogus", bogus_money,None, RSA.PublicKeychain(e=keys['e'],n=keys['n']) )

    #bogus wymysla X
    x = random.randint(0,10)

    #m = (x^e mod n)− J + 1
    Bogus_message = ciphering.encrypt(x) - Bogus.cash_amount + 1 

    #apolonia wymysla p << n
    p=random.randint(1,10)

    #{ 0<j<MAX_CASH  | (m + j − 1)^d mod p }
    Zi = [ciphering.decrypt(Bogus_message + j-1) % p  for j in range(1,MAX_CASH+1)]

    # x+1 dla kazdego x, ktorego index jest wiekszy niz ilosc pieniedzy apolonii
    Wj = list(map(lambda tup: tup[1]+1 if tup[0]+1>Apolinia.cash_amount else tup[1],enumerate(Zi)) )

    #Bogus sprawdza czy liczba na pozycji odpowiadajacej ilosci pieniedzy bogusia
    #jest wzglednie pierwsza z x mod p 
    Bogus_is_wealthier = gcd(Wj[Bogus.cash_amount-1],x%p) ==1
    return Bogus_is_wealthier
