import random
from rsa_keygen import RSAKeygen
from rsa_encrypt import RSAEncrypt

max_millions = 1000

alice_cash = int(input('alice$ '))
bob_cash = int(input('bob$ '))


keystore = RSAKeygen()
keystore.generate()

encryptor = RSAEncrypt(keystore.n, keystore.e)
decryptor = RSAEncrypt(keystore.n, keystore.d)

# bob
bob_x = random.randint(1, max_millions)
encrypted_bob_x = encryptor.encrypt_int(bob_x)
m = encrypted_bob_x - bob_cash + 1

# alice
Y = []
for i in range(0, max_millions):
    Y.append(decryptor.encrypt_int(m + i - 1))

Z = [y % keystore.p for y in Y]

for i in range(alice_cash, max_millions):
    Z[i] += 1

# Bob
if Z[bob_cash] == (bob_x % keystore.p):
    print('alice ma więcej pesos')
else:
    print('bob ma więcej pesos')