import random
from rsa_keygen import RSAKeygen
from rsa_encrypt import RSAEncrypt
from colorama import init, Fore, Back, Style

max_millions = 1000


def bobprint(string):
    print(f'{Fore.BLUE}{string}{Style.RESET_ALL}')

def aliceprint(string):
    print(f'{Fore.RED}{string}{Style.RESET_ALL}')

alice_cash = int(input(f'{Fore.RED}alice{Style.RESET_ALL}$ '))
bob_cash = int(input(f'{Fore.BLUE}bob{Style.RESET_ALL}$ '))

print('Generating RSA keys!')
keystore = RSAKeygen()
keystore.generate()

encryptor = RSAEncrypt(keystore.n, keystore.e)
decryptor = RSAEncrypt(keystore.n, keystore.d)

# bob
bobprint('Bob got public key.')
bob_x = random.randint(1, max_millions)
bobprint(f'Bob x: {bob_x}')
encrypted_bob_x = encryptor.encrypt_int(bob_x)
bobprint(f'Bob encrypted x: {encrypted_bob_x}')
m = encrypted_bob_x - bob_cash + 1
bobprint(f'Bob m: {m}')

# alice
Y = []
for i in range(0, max_millions):
    Y.append(decryptor.encrypt_int(m + i - 1))
aliceprint('Alice generated Y array')

Z = [y % keystore.p for y in Y]
aliceprint('Alice generated Z array')

for i in range(alice_cash, max_millions):
    Z[i] += 1

# Bob
if Z[bob_cash] == (bob_x % keystore.p):
    print('alice ma więcej pesos')
else:
    print('bob ma więcej pesos')
