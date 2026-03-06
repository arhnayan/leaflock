import json
import os
import struct

from . import crypto, kdf
from .exceptions import InvalidKeyfileError, InvalidPassphraseError, WrongMachineError
from .machine_id import get_machine_id


KEYFILE_MAGIC = b"LEAFKEY\x00\x01"
KEYFILE_VERSION = 1


def _pack_keyfile(machine_ids: list, encrypted_master_key: bytes, nonce: bytes) -> bytes:
    version_bytes = struct.pack("B", KEYFILE_VERSION)
    machine_ids_json = json.dumps(machine_ids).encode("utf-8")
    machine_ids_len = struct.pack("!H", len(machine_ids_json))
    key_len = struct.pack("!H", len(encrypted_master_key))
    nonce_len = struct.pack("B", len(nonce))
    return KEYFILE_MAGIC + version_bytes + machine_ids_len + machine_ids_json + key_len + encrypted_master_key + nonce_len + nonce


def _unpack_keyfile(data: bytes) -> tuple:
    if not data.startswith(KEYFILE_MAGIC):
        raise InvalidKeyfileError("Invalid keyfile format")
    
    offset = len(KEYFILE_MAGIC)
    version = struct.unpack("B", data[offset:offset+1])[0]
    offset += 1
    
    machine_ids_len = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2
    machine_ids_json = data[offset:offset+machine_ids_len].decode("utf-8")
    machine_ids = json.loads(machine_ids_json)
    offset += machine_ids_len
    
    key_len = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2
    encrypted_master_key = data[offset:offset+key_len]
    offset += key_len
    
    nonce_len = struct.unpack("B", data[offset:offset+1])[0]
    offset += 1
    nonce = data[offset:offset+nonce_len]
    
    return machine_ids, encrypted_master_key, nonce


def create_keyfile(passphrase: str, machine_ids: list, output_path: str) -> None:
    master_key = os.urandom(32)
    salt = os.urandom(16)
    key = kdf.derive_key(passphrase, salt)
    
    encrypted_master_key = crypto.encrypt(master_key, key)
    nonce = os.urandom(12)
    
    keyfile_data = _pack_keyfile(machine_ids, encrypted_master_key, nonce)
    keyfile_data = salt + keyfile_data
    
    with open(output_path, "wb") as f:
        f.write(keyfile_data)
    os.chmod(output_path, 0o600)


def load_keyfile(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    
    salt = data[:16]
    keyfile_body = data[16:]
    
    machine_ids, encrypted_master_key, _ = _unpack_keyfile(keyfile_body)
    
    return {
        "machine_ids": machine_ids,
        "encrypted_master_key": encrypted_master_key,
        "salt": salt,
    }


def decrypt_keyfile(path: str, passphrase: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    
    salt = data[:16]
    keyfile_body = data[16:]
    
    machine_ids, encrypted_master_key, _ = _unpack_keyfile(keyfile_body)
    
    key = kdf.derive_key(passphrase, salt)
    
    try:
        master_key = crypto.decrypt(encrypted_master_key, key)
    except Exception as e:
        raise InvalidPassphraseError("Invalid passphrase") from e
    
    current_machine_id = get_machine_id()
    if current_machine_id not in machine_ids:
        raise WrongMachineError("This keyfile is not authorized for this machine")
    
    return master_key


def add_machine_to_keyfile(path: str, new_machine_id: str, passphrase: str) -> None:
    with open(path, "rb") as f:
        data = f.read()
    
    salt = data[:16]
    keyfile_body = data[16:]
    
    machine_ids, encrypted_master_key, _ = _unpack_keyfile(keyfile_body)
    
    if new_machine_id in machine_ids:
        return
    
    derived_key = kdf.derive_key(passphrase, salt)
    
    try:
        master_key = crypto.decrypt(encrypted_master_key, derived_key)
    except Exception as e:
        raise InvalidPassphraseError("Invalid passphrase") from e
    
    current_machine_id = get_machine_id()
    if current_machine_id not in machine_ids:
        raise WrongMachineError("This keyfile is not authorized for this machine")
    
    machine_ids.append(new_machine_id)
    
    new_encrypted = crypto.encrypt(master_key, derived_key)
    nonce = os.urandom(12)
    new_keyfile_data = _pack_keyfile(machine_ids, new_encrypted, nonce)
    new_data = salt + new_keyfile_data
    
    with open(path, "wb") as f:
        f.write(new_data)
    os.chmod(path, 0o600)


def remove_machine_from_keyfile(path: str, machine_id_to_remove: str, passphrase: str) -> None:
    with open(path, "rb") as f:
        data = f.read()
    
    salt = data[:16]
    keyfile_body = data[16:]
    
    machine_ids, encrypted_master_key, _ = _unpack_keyfile(keyfile_body)
    
    if machine_id_to_remove not in machine_ids:
        return
    
    derived_key = kdf.derive_key(passphrase, salt)
    
    try:
        master_key = crypto.decrypt(encrypted_master_key, derived_key)
    except Exception as e:
        raise InvalidPassphraseError("Invalid passphrase") from e
    
    current_machine_id = get_machine_id()
    if current_machine_id not in machine_ids:
        raise WrongMachineError("This keyfile is not authorized for this machine")
    
    machine_ids = [m for m in machine_ids if m != machine_id_to_remove]
    
    new_encrypted = crypto.encrypt(master_key, derived_key)
    nonce = os.urandom(12)
    new_keyfile_data = _pack_keyfile(machine_ids, new_encrypted, nonce)
    new_data = salt + new_keyfile_data
    
    with open(path, "wb") as f:
        f.write(new_data)
    os.chmod(path, 0o600)
