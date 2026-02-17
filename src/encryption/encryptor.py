"""
Legacy Encryptor - thin wrapper around AESEngine.

Uses the streaming-capable AES-256-GCM implementation provided by AESEngine,
so large files are processed in 64KB chunks rather than being fully loaded
into memory.

For new code, prefer encryption.algorithms.get_algorithm() and AESEngine
directly, but this class remains for backward compatibility.
"""

from typing import Callable, Optional

from .aes_engine import AESEngine


class Encryptor:
    """Backward-compatible encryptor using AES-256."""

    def __init__(self, password: str):
        self._engine = AESEngine(password)

    def encrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        delete_original: bool = False,
    ) -> str:
        """
        Encrypt a file using AES-256-GCM.

        Delegates to AESEngine.encrypt_file, which now performs chunk-based
        streaming encryption while preserving the on-disk format.
        """
        return self._engine.encrypt_file(
            file_path,
            output_path=output_path,
            progress_callback=progress_callback,
            delete_original=delete_original,
        )
 