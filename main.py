from ocb.ocb import AES_OCB

message = "mówi hymel jadwiga lipinki łużyckie!! łączna 43.. łączna tutaj jak się wjeżdża.. zaraz! koło poczty!"
associated_data = "proszę nie parkować!"

tag_size = 15
key = bytearray(b"konceptualizacja")
nonce = bytearray(b"interpunkcja")

ocb = AES_OCB(key, nonce, tag_size)

message_bytes = bytearray(message.encode('utf-8'))
ad_bytes = bytearray(associated_data.encode('utf-8'))

ciphertext = ocb.encrypt(message_bytes, ad_bytes)

print(ciphertext)

