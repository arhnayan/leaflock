import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(passphrase.encode())


def verify_key(passphrase: str, salt: bytes, key: bytes) -> bool:
    try:
        computed = derive_key(passphrase, salt)
        return computed == key
    except Exception:
        return False
