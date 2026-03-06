import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC_HEADER = b"LEAFLOCK\x00\x01"


def encrypt(data: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return MAGIC_HEADER + nonce + ciphertext


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if not ciphertext.startswith(MAGIC_HEADER):
        raise ValueError("Invalid file format")
    nonce = ciphertext[10:22]
    actual_ciphertext = ciphertext[22:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, actual_ciphertext, None)
