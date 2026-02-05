"""
Legacy Decryptor - handles both AES-256-GCM and legacy AES-CBC .enc files.
For new code, use encryption.algorithms.get_algorithm() and AESEngine directly.
"""

from .aes_engine import AESEngine


class Decryptor:
    """Backward-compatible decryptor for AES-encrypted files."""

    def __init__(self, password: str):
        self._engine = AESEngine(password)

    def decrypt_file(self, encrypted_file_path: str) -> str:
        """Decrypts AES encrypted file. Returns decrypted file path."""
        return self._engine.decrypt_file(encrypted_file_path)
