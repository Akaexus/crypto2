import sys

from ocb.ocb import AES_OCB
from gcm.gcm import AES_GCM
def call_ocb():
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

def call_gcm():
    # gcm = AES_GCM()
    key = b'prokrastynacjaxD'
    iv = b"bibliografia"

    message_bytes = message.encode('utf-8')
    ad_bytes = associated_data.encode('utf-8')
    gcm = AES_GCM(key, iv)

    encrypted, auth_tag = gcm.encrypt(message_bytes, ad_bytes)
    print(encrypted)
    print(auth_tag)

message = "mowi hymel jadwiga lipinki luzyckie!! laczna 43.. laczna tutaj jak sie wjezdza.. zaraz! kolo pocz"
associated_data = "prosze nie parkowac!"

call_gcm()