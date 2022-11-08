import sys

from Crypto.Cipher import AES

# https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
class AES_GCM:
    def __init__(self, k: bytearray | bytes, initial_value: bytearray | bytes):
        self.key = k
        self.iv = initial_value
        self.aes = AES.new(self.key, AES.MODE_ECB)
        self.H = self.aes.encrypt(b'\x00'*16)
        # precompute the table for multiplication in finite field
        table = []  # for 8-bit
        for i in range(16):
            row = []
            for j in range(256):
                row.append(AES_GCM.gf_2_128_mul(AES_GCM.b2i(self.H), j << (8 * i)))
            table.append(tuple(row))
        self.__pre_table = tuple(table)

    @staticmethod
    def b2i(b: bytes) -> int:
        return int.from_bytes(b, sys.byteorder)

    @staticmethod
    def i2b(i: int, size=16) -> bytes:
        return i.to_bytes(size, sys.byteorder)

    @staticmethod
    def split_block(data: bytes | bytearray, size: int):
        for i in range(0, len(data), size):
            d = data[i:i + size]
            yield data[i:i + size]

    @staticmethod
    def gf_2_128_mul(a, b):
        R = 0b11100001 << 120
        # store the product in p
        result = 0

        # iterate over bits in b
        for i in range(128):
            # check if i-th bit is one
            if b & (1 << (127 - i)):
                result ^= a  # adds polynomial a to p

            if a & 1:
                a = (a >> 1) ^ R
            else:
                a >>= 1
        return result
    @staticmethod
    def pad(data):
        return data + b'\x00' * (16 - (len(data) % 16))

    def __times_auth_key(self, val):
        res = 0
        for i in range(16):
            res ^= self.__pre_table[i][val & 0xFF]
            val >>= 8
        return res

    def ghash(self, aad: bytes, ciphertext: bytes) -> int:
        len_aad = len(aad)
        len_ciphertext = len(ciphertext)

        # pad
        aad = AES_GCM.pad(aad)
        ciphertext = AES_GCM.pad(ciphertext)

        data = aad + ciphertext
        tag = 0

        for block in AES_GCM.split_block(data, 16):
            tag ^= AES_GCM.b2i(block)
            tag = self.__times_auth_key(tag)

        tag ^= ((8 * len_aad) << 64) | (8 * len_ciphertext)
        tag = self.__times_auth_key(tag)
        return tag



    def encrypt(self, plaintext: bytes, additional_data: bytes) -> (bytes, bytes):
        # initialize the counter to iv || 0^31 1
        # this does not support other iv length than 96b
        y = AES_GCM.b2i(self.iv) << 32 | 0x01

        e_y0 = self.aes.encrypt(AES_GCM.i2b(y))
        ciphertext_all = b''
        for block in AES_GCM.split_block(plaintext, 16):
            y += 1
            ciphertext = AES_GCM.b2i(self.aes.encrypt(AES_GCM.i2b(y))) ^ AES_GCM.b2i(block)
            ciphertext_all += AES_GCM.i2b(ciphertext)

        auth_tag = self.ghash(additional_data, ciphertext_all)
        auth_tag ^= AES_GCM.b2i(self.aes.encrypt(AES_GCM.i2b((AES_GCM.b2i(self.iv) << 32) | 1)))
        return ciphertext_all, AES_GCM.i2b(auth_tag)

    def decrypt(self, ciphertext: bytes, tag: bytes) -> (bytes, bool):
        return b'', True