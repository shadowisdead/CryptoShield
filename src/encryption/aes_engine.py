"""
AES-256-GCM encryption engine (password-based).
Also handles legacy AES-CBC format for backward compatibility.
"""

import os
from typing import Callable, Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #type: ignore

from core.secure_delete import secure_delete
from cryptography.hazmat.primitives import hashes #type: ignore
from cryptography.hazmat.backends import default_backend #type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes #type: ignore
from cryptography.hazmat.primitives import padding #type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM #type: ignore
from .base import EncryptionAlgorithm


class AESEngine(EncryptionAlgorithm):
    """AES-256-GCM authenticated encryption. Backward compatible with legacy AES-CBC."""

    VERSION = 1
    LEGACY_MAGIC = b""  # No version header = legacy

    def __init__(self, password: str):
        self.password = password.encode("utf-8")
        self.backend = default_backend()

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
        nonce = os.urandom(12)  # GCM standard nonce size
        key = self._derive_key(salt)

        aesgcm = AESGCM(key)
        total = os.path.getsize(file_path)

        with open(file_path, "rb") as f:
            data = f.read()

        self._report_progress(progress_callback, total // 2, total)
        encrypted = aesgcm.encrypt(nonce, data, None)
        self._report_progress(progress_callback, total, total)

        out = output_path or (file_path + ".enc")
        with open(out, "wb") as f:
            f.write(bytes([self.VERSION, 1]))  # version, algo_id=1 (AES-GCM)
            f.write(salt)
            f.write(nonce)
            f.write(encrypted)

        if delete_original:
            secure_delete(file_path)

        return out

    def decrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        with open(file_path, "rb") as f:
            raw = f.read()

        # Check for new format (version byte)
        if len(raw) >= 2:
            ver, algo = raw[0], raw[1]
            if ver == 1 and algo == 1:
                return self._decrypt_gcm(raw, file_path, output_path, progress_callback)

        # Legacy AES-CBC format
        return self._decrypt_legacy(raw, file_path, output_path, progress_callback)

    def _decrypt_gcm(
        self,
        raw: bytes,
        src_path: str,
        output_path: Optional[str],
        progress_callback: Optional[Callable[[int, int], None]],
    ) -> str:
        salt = raw[2:18]
        nonce = raw[18:30]
        ciphertext = raw[30:]
        key = self._derive_key(salt)
        aesgcm = AESGCM(key)
        data = aesgcm.decrypt(nonce, ciphertext, None)
        total = len(raw)
        self._report_progress(progress_callback, total, total)

        if output_path is None:
            if src_path.endswith(".enc"):
                output_path = src_path[:-4] + "_decrypted"
            else:
                output_path = src_path + "_decrypted"

        with open(output_path, "wb") as f:
            f.write(data)
        return output_path

    def _decrypt_legacy(
        self,
        raw: bytes,
        src_path: str,
        output_path: Optional[str],
        progress_callback: Optional[Callable[[int, int], None]],
    ) -> str:
        salt = raw[:16]
        iv = raw[16:32]
        encrypted_data = raw[32:]
        key = self._derive_key(salt)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend,
        )
        decryptor = cipher.decryptor()
        padded = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()

        total = len(raw)
        self._report_progress(progress_callback, total, total)

        if output_path is None:
            if src_path.endswith(".enc"):
                output_path = src_path.replace(".enc", "_decrypted")
            else:
                output_path = src_path + "_decrypted"

        with open(output_path, "wb") as f:
            f.write(data)
        return output_path

    @property
    def algorithm_name(self) -> str:
        return "AES-256"
