"""
Legacy Decryptor - handles both AES-256-GCM and legacy AES-CBC .enc files.

This now benefits from the streaming-aware AESEngine implementation, so
large encrypted files can be decrypted without loading the entire ciphertext
into memory at once.

For new code, use encryption.algorithms.get_algorithm() and AESEngine directly.
"""

from typing import Callable, Optional

from .aes_engine import AESEngine


class Decryptor:
    """Backward-compatible decryptor for AES-encrypted files."""

    def __init__(self, password: str):
        self._engine = AESEngine(password)

    def decrypt_file(
        self,
        encrypted_file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        """
        Decrypt an AES-encrypted file.

        Returns path to the decrypted file.
        """
        return self._engine.decrypt_file(
            encrypted_file_path,
            output_path=output_path,
            progress_callback=progress_callback,
        )
