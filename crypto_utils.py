from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def describe_bytes(title, data_bytes):
    """Return a helper dictionary with hex and length details for UI rendering."""
    return {
        "label": title,
        "hex": data_bytes.hex(),
        "length_bytes": len(data_bytes),
    }

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
    padded = pad(plaintext.encode())
    encrypted = encryptor.update(padded) + encryptor.finalize()
    payload = iv + encrypted
    return {
        "ciphertext": payload.hex(),
        "iv": iv.hex(),
        "algorithm": "AES-256-CBC",
        "padded_plaintext": padded.hex(),
        "padding_length": padded[-1],
        "blocks": [
            describe_bytes("IV (16 bytes)", iv),
            describe_bytes("Ciphertext blocks", encrypted),
        ],
    }

def aes_decrypt(key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)
    data = bytes.fromhex(ciphertext_hex)
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ct) + decryptor.finalize()
    unpadded = unpad(decrypted)
    return {
        "plaintext": unpadded.decode(),
        "iv": iv.hex(),
        "algorithm": "AES-256-CBC",
        "ciphertext": ciphertext_hex,
        "padded_plaintext": decrypted.hex(),
        "padding_length": decrypted[-1],
        "steps": [
            describe_bytes("Extracted IV", iv),
            describe_bytes("Ciphertext portion", ct),
            describe_bytes("After AES-CBC decrypt (still padded)", decrypted),
        ],
    }
