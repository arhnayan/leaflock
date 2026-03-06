import os
import re
from typing import Dict

from . import crypto
from .exceptions import CorruptedFileError


ENV_COMMENT = re.compile(r"^\s*#")
ENV_LINE = re.compile(r'^([^=]+)=(.*)$')


def parse_env_file(path: str) -> Dict[str, str]:
    result = {}
    if not os.path.exists(path):
        return result
    
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n\r")
            if ENV_COMMENT.match(line):
                continue
            match = ENV_LINE.match(line)
            if match:
                key = match.group(1).strip()
                value = match.group(2).strip()
                if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
                    value = value[1:-1]
                elif len(value) >= 2 and value[0] == "'" and value[-1] == "'":
                    value = value[1:-1]
                result[key] = value
    return result


def write_env_file(path: str, data: Dict[str, str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for key, value in data.items():
            if " " in value or "\n" in value or '"' in value:
                f.write(f'{key}="{value}"\n')
            else:
                f.write(f"{key}={value}\n")


def encrypt_env_file(input_path: str, output_path: str, key: bytes) -> None:
    data = parse_env_file(input_path)
    content = str(data).encode("utf-8")
    encrypted = crypto.encrypt(content, key)
    with open(output_path, "wb") as f:
        f.write(encrypted)
    os.chmod(output_path, 0o600)


def decrypt_env_file(input_path: str, key: bytes) -> Dict[str, str]:
    with open(input_path, "rb") as f:
        encrypted = f.read()
    
    try:
        decrypted = crypto.decrypt(encrypted, key)
    except Exception as e:
        raise CorruptedFileError("Failed to decrypt file") from e
    
    content = decrypted.decode("utf-8")
    data = eval(content)
    return data
