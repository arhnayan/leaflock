# leaflock

Machine-bound `.env` encryption for Python.

Encrypt your `.env` files so they only work on the machine that created them. Even if someone copies your `.env.locked` file to another machine, it's useless.

## Installation

```bash
pip install leaflock
```

## Quick Start

### Encrypt a .env file

```bash
leaflock encrypt .env -o .env.locked -p "your-passphrase"
```

This creates:
- `.env.locked` - encrypted secrets
- `.env.locked.key` - keyfile (machine-bound)

### Decrypt a .env file

```bash
leaflock decrypt .env.locked -o .env -p "your-passphrase"
```

### Python API

```python
from leaflock import load_dotenv

load_dotenv(".env.locked", passphrase="your-passphrase")
```

Or use environment variable:

```bash
export LEAFLOCK_PASSPHRASE="your-passphrase"
python your_app.py
```

## Multi-Machine Support

Add another machine to authorized list:

```bash
leaflock add-machine .env.locked.key -m <machine-id> -p "your-passphrase"
```

Get current machine ID:

```bash
python -c "from leaflock import machine_id; print(machine_id.get_machine_id())"
```

## Security

- AES-256-GCM encryption
- PBKDF2 key derivation (480,000 iterations)
- Machine ID binding (works on Linux, macOS, Windows)
- File permissions set to 0600

## Requirements

- Python 3.9+
- cryptography
- click
