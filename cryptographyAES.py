from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes

from Crypto.Util.Padding import pad, unpad

import os



def generate_aes_key(secrete_key_path, key_size=16):
    secrete_key = get_random_bytes(key_size)
    with open(secrete_key_path, 'wb') as secrete_key_file:
        secrete_key_file.write(secrete_key)
    return secrete_key



def encrypt_data(data, secrete_key):
    iv = get_random_bytes(16)
    cipher = AES.new(secrete_key, AES.MODE_CBC, iv)
    padded_data = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext

def encrypt_file(file_path, key_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    with open(key_path, 'rb') as file:
        secrete_key = file.read()
    encrypted_data = encrypt_data(file_data, secrete_key)
    with open(file_path, 'wb') as file:
                file.write(encrypted_data)


def decrypt_data(ciphertext, secrete_key):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = AES.new(secrete_key, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(actual_ciphertext)
    data = unpad(padded_data, AES.block_size)
    return data

def decrypt_file(file_path, key_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    with open(key_path, 'rb') as file:
        secrete_key = file.read()
    encrypted_data = decrypt_data(file_data, secrete_key)
    with open(file_path, 'wb') as file:
                file.write(encrypted_data)



