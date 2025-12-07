from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

def aes_encrypt(key_hex, plaintext):
    key = bytes.fromhex(key_hex)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(pad(plaintext.encode())) + encryptor.finalize()
    return (iv + encrypted).hex()

def aes_decrypt(key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)
    data = bytes.fromhex(ciphertext_hex)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ct) + decryptor.finalize()
    return unpad(decrypted).decode()
