"""
ChaCha20-Poly1305 encryption engine (password-based).

Note: cryptography's ChaCha20Poly1305 API is single-shot (non-streaming).
We keep the authenticated one-shot design for integrity; for very large files,
prefer the AES-256 engine which supports true streaming I/O.
"""

import os
from typing import Callable, Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #type: ignore
from core.logger import get_logger
from core.secure_delete import secure_delete
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # type: ignore

from .base import EncryptionAlgorithm


class ChaChaEngine(EncryptionAlgorithm):
    """ChaCha20-Poly1305 AEAD encryption."""

    VERSION = 1
    ALGO_ID = 2

    def __init__(self, password: str):
        self.password = password.encode("utf-8")
        self.backend = default_backend()
        self._logger = get_logger()

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
            backend=self.backend,
        )
        return kdf.derive(self.password)

    def _report_progress(
        self, callback: Optional[Callable[[int, int], None]], done: int, total: int
    ) -> None:
        if callback and total > 0:
            callback(min(done, total), total)

    def encrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        delete_original: bool = False,
    ) -> str:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt)
        chacha = ChaCha20Poly1305(key)

        with open(file_path, "rb") as f:
            data = f.read()

        total = len(data)
        self._report_progress(progress_callback, total // 2, total)
        encrypted = chacha.encrypt(nonce, data, None)
        self._report_progress(progress_callback, total, total)

        out = output_path or (file_path + ".enc")
        with open(out, "wb") as f:
            f.write(bytes([self.VERSION, self.ALGO_ID]))
            f.write(salt)
            f.write(nonce)
            f.write(encrypted)

        if delete_original:
            secure_delete(file_path)

        self._logger.info("Encrypted file '%s' with ChaCha20", file_path)
        return out

    def decrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        with open(file_path, "rb") as f:
            raw = f.read()

        if len(raw) < 2 + 16 + 12:
            raise ValueError("Invalid ChaCha20 encrypted file")

        ver, algo = raw[0], raw[1]
        if ver != 1 or algo != self.ALGO_ID:
            raise ValueError("File was not encrypted with ChaCha20")

        salt = raw[2:18]
        nonce = raw[18:30]
        ciphertext = raw[30:]

        key = self._derive_key(salt)
        chacha = ChaCha20Poly1305(key)
        try:
            data = chacha.decrypt(nonce, ciphertext, None)
        except Exception:
            # Authentication failure, typically due to wrong password.
            logger = self._logger
            logger.error("Failed to decrypt '%s' with ChaCha20 (authentication error)", file_path)
            raise

        total = len(raw)
        self._report_progress(progress_callback, total, total)

        if output_path is None:
            if file_path.endswith(".enc"):
                output_path = file_path[:-4] + "_decrypted"
            else:
                output_path = file_path + "_decrypted"

        with open(output_path, "wb") as f:
            f.write(data)
        self._logger.info("Decrypted file '%s' with ChaCha20", file_path)
        return output_path

    @property
    def algorithm_name(self) -> str:
        return "ChaCha20"
