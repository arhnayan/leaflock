# Changelog

## v0.1.0 (2026-03-06)

Initial release.

### Added
- Machine-bound .env encryption (AES-256-GCM)
- Cross-platform machine ID detection (Linux, macOS, Windows)
- CLI tool: encrypt, decrypt, add-machine, remove-machine
- Python API: load_dotenv() drop-in replacement
- Keyfile management with multi-machine support
- PBKDF2 key derivation (480,000 iterations)
- Secure file permissions (0600)
