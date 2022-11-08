from ocb.ocb import AES_OCB

message = "mowi hymel jadwiga lipinki luzyckie!! laczna 43.. laczna tutaj jak sie wjezdza.. zaraz! kolo pocz"
associated_data = "prosze nie parkowac!"

tag_size = 15
key = bytearray(b"konceptualizacja")
nonce = bytearray(b"interpunkcja")

ocb = AES_OCB(key, nonce, tag_size)

message_bytes = bytearray(message.encode('utf-8'))
ad_bytes = bytearray(associated_data.encode('utf-8'))


ciphertext = ocb.encrypt(message_bytes, ad_bytes)


decrypted, valid = ocb.decrypt(ciphertext, ad_bytes)
print('\n'*3)
print('message: ', message)
print('ciphertext: ', ciphertext)
print('decrypted: ', decrypted.decode('utf-8'))
print('valid: ', valid)

