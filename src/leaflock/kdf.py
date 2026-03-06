from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError


ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID,
)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    return ph.hash(passphrase + salt.hex()).encode()


def verify_key(passphrase: str, salt: bytes, key: bytes) -> bool:
    try:
        computed = derive_key(passphrase, salt)
        return computed == key
    except (VerifyMismatchError, Exception):
        return False
