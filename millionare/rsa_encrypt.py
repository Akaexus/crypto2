import sys
import math

class RSAEncrypt:
    def __init__(self, pk_n, pk_e):
        # open public key
        self.n = pk_n
        self.e = pk_e

        # open message

    def encrypt(self, payload: bytes) -> bytes:
        ciphertext = b''
        chunk_size = RSAEncrypt.calculate_chunk_size(self.n)
        n_size = math.ceil(RSAEncrypt.get_int_size(self.n) / 8)
        # pad message
        # add 0x00 bytes to match chunk size
        for i in range(chunk_size - (len(payload) % chunk_size)):
            payload += b'\0'
        for chunk in RSAEncrypt.chunks(payload, chunk_size):
            m = self.encrypt_int(int.from_bytes(chunk, byteorder=sys.byteorder))
            ciphertext += int.to_bytes(m, n_size, byteorder=sys.byteorder)
        return ciphertext

    def encrypt_int(self, m):
        w = 1
        bits = []
        a = self.e
        n = self.n
        while a:
            bits.append(a & 1)
            a >>= 1
        bits = bits[::-1]

        for bit in bits:
            w = w ** 2 % n
            if bit == 1:
                w = w * m % n
        return w

    @staticmethod
    def get_int_size(_n):
        b = 0
        while _n:
            b += 1
            _n >>=1
        return b

    @staticmethod
    def calculate_chunk_size(number):
        b = RSAEncrypt.get_int_size(number)
        return b // 8

    @staticmethod
    def chunks(lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

# encryptor = RSAEncrypt('id_rsa.pub', 'message.txt', 'encrypted.txt')

# for char in payload:
#     print(encrypt(char, e, n))
# encrypted = encrypt(payload, e, n)
# with open(destination_file, 'w') as f:
#     f.write(str(encrypted))