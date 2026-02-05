"""
Legacy Encryptor - uses AES-256-GCM (backward compatible with .enc files).
For new code, use encryption.algorithms.get_algorithm() and AESEngine directly.
"""

from .aes_engine import AESEngine


class Encryptor:
    """Backward-compatible encryptor using AES-256."""

    def __init__(self, password: str):
        self._engine = AESEngine(password)

    def encrypt_file(self, file_path: str) -> str:
        """Encrypts a file using AES-256-GCM. Returns encrypted file path."""
        return self._engine.encrypt_file(file_path)
