__version__ = "0.1.0"

import os
from typing import Optional

from . import env_file, keyfile
from .exceptions import LeaflockError, WrongMachineError
from .machine_id import get_machine_id


def load_dotenv(dotenv_path: str = ".env.locked", override: bool = False, passphrase: Optional[str] = None) -> bool:
    keyfile_path = dotenv_path + ".key"
    
    if not os.path.exists(dotenv_path):
        if os.path.exists(".env"):
            return False
        return False
    
    if not os.path.exists(keyfile_path):
        raise LeaflockError(f"Keyfile not found: {keyfile_path}")
    
    if passphrase is None:
        passphrase = os.environ.get("LEAFLOCK_PASSPHRASE", "")
        if not passphrase:
            raise LeaflockError("Passphrase required. Set LEAFLOCK_PASSPHRASE env var or pass passphrase parameter.")
    
    try:
        key = keyfile.decrypt_keyfile(keyfile_path, passphrase)
    except WrongMachineError:
        raise WrongMachineError("This keyfile is not authorized for this machine")
    
    data = env_file.decrypt_env_file(dotenv_path, key)
    
    for key, value in data.items():
        if override or key not in os.environ:
            os.environ[key] = value
    
    return True
