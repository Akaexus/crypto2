from Crypto.Cipher import AES
import sys

# https://www.cs.ucdavis.edu/~rogaway/ocb/ocb-faq.htm#what-is-ocb
class AES_OCB:
    MASK_128 = 0xffffffffffffffffffffffffffffffff
    BLOCK_SIZE = 16

    def __init__(self, k: bytearray | bytes, n: bytearray | bytes, tag_size: int):
        if not (0 <= tag_size <= 16):
            raise ValueError("Tag size (in bytes) is not valid!")

        self.tag_size = tag_size
        self.key = k
        self.nonce = int.from_bytes(n, sys.byteorder)
        self.aes = AES.new(self.key, AES.MODE_ECB)

    def print_byte_array(self, ba: bytearray, format=bin):
        formats = {
            bin: '{0:08b}',
            hex: '{0:02x}'
        }
        b = ''.join([formats[format].format(x) for x in ba])
        print(f'{b} ({len(b) if format == bin else len(b)*4})')

    @staticmethod
    def byte_xor(ba1: bytes, ba2: bytes):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def print(self, b: int, type=bin):
        if type == bin:
            print('{0:0128b}'.format(b))
        elif type == hex:
            print('{0:0x}'.format(b))

    def calculate_init(self):
        # calculate init value
        # extract last 6 bits
        bottom = self.nonce & 0b111111

        top = 0x00000001 << 96 | self.nonce & 0xffffffffffffffffffffffffffffffc0

        ktop = int.from_bytes(self.aes.encrypt(top.to_bytes(16, sys.byteorder)), sys.byteorder)

        # Stretch = Ktop || (Ktop xor (Ktop << 8))
        strech = ktop << 128 | ktop ^ (ktop << 8 & AES_OCB.MASK_128)

        init_n = strech << bottom & 0xffffffffffffffffffffffffffffffff00000000000000000000000000000000  # keep 256b
        init_n >>= 128 # get left 128 bits
        return init_n
    @staticmethod
    def double(s: int):
        first_bit = s >> 127
        # let double(S) = S << 1 if the first bit of S is 0
        s = (s << 1) % AES_OCB.MASK_128
        if first_bit:  # let double(S) = (S << 1)⊕135 otherwise
            s ^= 135
        return s

    @staticmethod
    def split_block(data: bytes | bytearray, size: int):
        for i in range(0, len(data), size):
            d = data[i:i + size]
            yield data[i:i + size]

    @staticmethod
    def calculate_l(ldollar: int, i: int):
        l = AES_OCB.double(ldollar)
        while i & 0x01 == 0:
            l = AES_OCB.double(l)
            i >>= 1
        return l

    @staticmethod
    def pad(d: bytes):
        if len(d) < AES_OCB.BLOCK_SIZE:
            d = d + b'\x80'
        while len(d) < AES_OCB.BLOCK_SIZE:
            d = d + b'\x00'
        return d

    def calculate_auth(self, associated_data: bytearray) -> int:
        delta = 0
        lstar = self.aes.encrypt(b'\x00'*16)
        ldollar = AES_OCB.double(int.from_bytes(lstar, sys.byteorder))
        auth = None
        i = 1
        for data_block in AES_OCB.split_block(associated_data, AES_OCB.BLOCK_SIZE):
            delta = delta ^ AES_OCB.calculate_l(ldollar, i)

            # pad block if needed
            if len(data_block) != AES_OCB.BLOCK_SIZE:
                data_block = AES_OCB.pad(data_block)

            data_block_int = int.from_bytes(data_block, sys.byteorder)
            ek = self.aes.encrypt((data_block_int ^ delta).to_bytes(AES_OCB.BLOCK_SIZE, sys.byteorder))
            if i == 1:
                auth = int.from_bytes(ek, sys.byteorder)
            else:
                auth ^= int.from_bytes(ek, sys.byteorder)
            i += 1
        return auth


    def encrypt(self, message: bytearray, associated_data: bytearray) -> bytes:
        ciphertext_all = b''
        auth = self.calculate_auth(associated_data)
        checksum = None
        delta = self.calculate_init()
        lstar = self.aes.encrypt(b'\x00'*16)
        ldollar = AES_OCB.double(int.from_bytes(lstar, sys.byteorder))
        i = 1
        for data_block in AES_OCB.split_block(message, AES_OCB.BLOCK_SIZE):
            delta = delta ^ AES_OCB.calculate_l(ldollar, i)
            data_block_int = int.from_bytes(data_block, sys.byteorder)
            # calculate checksum
            if i == 1:
                checksum = data_block_int
            else:
                checksum ^= data_block_int
            if len(data_block) == AES_OCB.BLOCK_SIZE:
                ek = self.aes.encrypt((data_block_int ^ delta).to_bytes(16, sys.byteorder))
                ciphertext = (int.from_bytes(ek, sys.byteorder) ^ delta).to_bytes(16, sys.byteorder)
            else:
                # data_block is not 128b
                padded_data_block = AES_OCB.pad(data_block)
                padded_data_block_int = int.from_bytes(padded_data_block, sys.byteorder)

                # calculate checksum
                checksum ^= padded_data_block_int
                ek = delta.to_bytes(AES_OCB.BLOCK_SIZE, sys.byteorder)
                ciphertext = (int.from_bytes(ek, sys.byteorder) ^ padded_data_block_int).to_bytes(16, sys.byteorder)
            ciphertext_all += ciphertext
            i += 1
        # calculate tag
        delta = delta ^ AES_OCB.calculate_l(ldollar, i)
        ek = int.from_bytes(self.aes.encrypt((checksum ^ delta).to_bytes(AES_OCB.BLOCK_SIZE, sys.byteorder)), sys.byteorder)
        tag = ek ^ auth

        tag_bytes = tag.to_bytes(AES_OCB.BLOCK_SIZE, sys.byteorder)[:self.tag_size]
        return ciphertext_all + tag_bytes
