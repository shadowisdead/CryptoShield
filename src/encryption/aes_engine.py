"""
AES-256-GCM encryption engine (password-based).
Also handles legacy AES-CBC format for backward compatibility.
"""

import os
from typing import Callable, Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore

from core.logger import get_logger
from core.secure_delete import secure_delete
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives.ciphers import (  # type: ignore
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives import padding  # type: ignore
from .base import EncryptionAlgorithm

CHUNK_SIZE = 65536  # 64KB chunks for streaming I/O


class AESEngine(EncryptionAlgorithm):
    """AES-256-GCM authenticated encryption. Backward compatible with legacy AES-CBC."""

    VERSION = 1
    LEGACY_MAGIC = b""  # No version header = legacy

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
        nonce = os.urandom(12)  # GCM standard nonce size
        key = self._derive_key(salt)

        total = os.path.getsize(file_path)
        out = output_path or (file_path + ".enc")

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()

        written = 0
        with open(file_path, "rb") as src, open(out, "wb") as dst:
            # Header: version, algo_id=1 (AES-GCM), salt, nonce
            dst.write(bytes([self.VERSION, 1]))
            dst.write(salt)
            dst.write(nonce)

            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                if ct:
                    dst.write(ct)
                written += len(chunk)
                self._report_progress(progress_callback, written, total)

            # Finalize and append authentication tag
            ct_final = encryptor.finalize()
            if ct_final:
                dst.write(ct_final)
            dst.write(encryptor.tag)

        if delete_original:
            secure_delete(file_path)

        self._logger.info("Encrypted file '%s' with AES-256", file_path)
        return out

    def decrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        # Inspect header to decide between GCM and legacy CBC format.
        with open(file_path, "rb") as f:
            header = f.read(2)

        if len(header) >= 2:
            ver, algo = header[0], header[1]
            if ver == 1 and algo == 1:
                return self._decrypt_gcm_stream(file_path, output_path, progress_callback)

        # Legacy AES-CBC format – fall back to original in-memory behavior.
        with open(file_path, "rb") as f:
            raw = f.read()
        out = self._decrypt_legacy(raw, file_path, output_path, progress_callback)
        self._logger.info("Decrypted legacy AES file '%s'", file_path)
        return out

    def _decrypt_gcm_stream(
        self,
        src_path: str,
        output_path: Optional[str],
        progress_callback: Optional[Callable[[int, int], None]],
    ) -> str:
        """
        Stream-decrypt AES-GCM file produced by this engine.

        File layout:
            [ver:1][algo_id:1][salt:16][nonce:12][ciphertext...][tag:16]
        """
        total = os.path.getsize(src_path)
        if total < 2 + 16 + 12 + 16:
            raise ValueError("Invalid AES-GCM encrypted file")

        with open(src_path, "rb") as src:
            # Header
            header = src.read(2)
            if len(header) != 2 or header[0] != self.VERSION or header[1] != 1:
                raise ValueError("File was not encrypted with AES-GCM")

            salt = src.read(16)
            nonce = src.read(12)
            if len(salt) != 16 or len(nonce) != 12:
                raise ValueError("Corrupted AES-GCM header")

            key = self._derive_key(salt)

            # Determine ciphertext and tag locations
            header_len = 2 + 16 + 12
            tag_len = 16
            ciphertext_len = total - header_len - tag_len
            if ciphertext_len < 0:
                raise ValueError("Invalid AES-GCM encrypted file")

            # Read tag from end of file, then stream ciphertext.
            src.seek(total - tag_len)
            tag = src.read(tag_len)
            if len(tag) != tag_len:
                raise ValueError("Failed to read authentication tag")

            from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher  # type: ignore

            cipher = _Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=self.backend,
            )
            decryptor = cipher.decryptor()

            if output_path is None:
                if src_path.endswith(".enc"):
                    output_path = src_path[:-4] + "_decrypted"
                else:
                    output_path = src_path + "_decrypted"

            # Stream ciphertext from its start position.
            src.seek(header_len)
            read_bytes = 0
            with open(output_path, "wb") as dst:
                while read_bytes < ciphertext_len:
                    to_read = min(CHUNK_SIZE, ciphertext_len - read_bytes)
                    chunk = src.read(to_read)
                    if not chunk:
                        break
                    pt = decryptor.update(chunk)
                    if pt:
                        dst.write(pt)
                    read_bytes += len(chunk)
                    self._report_progress(progress_callback, read_bytes, total)

                try:
                    final_pt = decryptor.finalize()
                except Exception:
                    # Authentication failure, typically due to wrong password.
                    self._logger.error(
                        "Failed to decrypt '%s' with AES-256 (authentication error)",
                        src_path,
                    )
                    raise
                if final_pt:
                    dst.write(final_pt)

        self._logger.info("Decrypted file '%s' with AES-256", src_path)
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
