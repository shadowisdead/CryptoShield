"""
RSA hybrid encryption: AES-256-GCM for file data, RSA for the session key.
Requires RSA keypair generation (user provides or we generate).
"""

import os
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding  # type: ignore
from cryptography.hazmat.primitives import serialization, hashes  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore

from core.logger import get_logger
from core.secure_delete import secure_delete
from .base import EncryptionAlgorithm

CHUNK_SIZE = 65536  # 64KB, aligned with AES engine


class RSAEngine(EncryptionAlgorithm):
    """
    Hybrid RSA+AES encryption.
    Uses RSA public key to encrypt a random AES key, then encrypts file with AES-GCM.
    """

    VERSION = 1
    ALGO_ID = 3
    RSA_KEY_SIZE = 2048

    def __init__(
        self,
        password: Optional[str] = None,
        public_key_path: Optional[str] = None,
        private_key_path: Optional[str] = None,
    ):
        """
        For encryption: provide public_key_path (or password to derive from stored key).
        For decryption: provide private_key_path + password (if key is encrypted).
        """
        self.password = (password or "").encode("utf-8")
        self.public_key_path = public_key_path
        self.private_key_path = private_key_path
        self._public_key = None
        self._private_key = None
        self._logger = get_logger()

        if public_key_path and os.path.exists(public_key_path):
            with open(public_key_path, "rb") as f:
                self._public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        if private_key_path and os.path.exists(private_key_path):
            with open(private_key_path, "rb") as f:
                pem = f.read()
            if self.password:
                self._private_key = serialization.load_pem_private_key(
                    pem, password=self.password, backend=default_backend()
                )
            else:
                self._private_key = serialization.load_pem_private_key(
                    pem, password=None, backend=default_backend()
                )

    @staticmethod
    def generate_keypair(
        public_path: str,
        private_path: str,
        password: Optional[str] = None,
    ) -> tuple[str, str]:
        """Generate RSA keypair and save to files. Returns (public_path, private_path)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSAEngine.RSA_KEY_SIZE,
            backend=default_backend(),
        )
        public_key = private_key.public_key()

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open(public_path, "wb") as f:
            f.write(pem_public)

        if password:
            enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            enc = serialization.NoEncryption()
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )
        with open(private_path, "wb") as f:
            f.write(pem_private)

        return public_path, private_path

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
        if not self._public_key:
            raise ValueError("RSA public key required for encryption. Load or generate keypair.")

        session_key = os.urandom(32)
        nonce = os.urandom(12)

        total = os.path.getsize(file_path)

        # Encrypt session key with RSA
        encrypted_key = self._public_key.encrypt(
            session_key + nonce,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        out = output_path or (file_path + ".enc")

        cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        written = 0
        with open(file_path, "rb") as src, open(out, "wb") as dst:
            dst.write(bytes([self.VERSION, self.ALGO_ID]))
            dst.write(len(encrypted_key).to_bytes(2, "big"))
            dst.write(encrypted_key)

            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                if ct:
                    dst.write(ct)
                written += len(chunk)
                self._report_progress(progress_callback, written, total)

            final_ct = encryptor.finalize()
            if final_ct:
                dst.write(final_ct)
            dst.write(encryptor.tag)

        if delete_original:
            secure_delete(file_path)

        self._logger.info("Encrypted file '%s' with RSA hybrid", file_path)
        return out

    def decrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        if not self._private_key:
            raise ValueError("RSA private key required for decryption.")

        total = os.path.getsize(file_path)
        if total < 4:
            raise ValueError("Invalid RSA encrypted file")

        with open(file_path, "rb") as src:
            header = src.read(2)
            if len(header) != 2:
                raise ValueError("Invalid RSA encrypted file")
            ver, algo = header[0], header[1]
            if ver != 1 or algo != self.ALGO_ID:
                raise ValueError("File was not encrypted with RSA hybrid")

            key_len_bytes = src.read(2)
            if len(key_len_bytes) != 2:
                raise ValueError("Invalid RSA encrypted file (missing key length)")
            key_len = int.from_bytes(key_len_bytes, "big")
            encrypted_key = src.read(key_len)
            if len(encrypted_key) != key_len:
                raise ValueError("Invalid RSA encrypted file (truncated key)")

        session_key_nonce = self._private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        session_key = session_key_nonce[:32]
        nonce = session_key_nonce[32:44]

        header_len = 2 + 2 + key_len
        tag_len = 16
        ciphertext_len = total - header_len - tag_len
        if ciphertext_len < 0:
            raise ValueError("Invalid RSA encrypted file (ciphertext too short)")

        # Read tag, set up decryptor, then stream ciphertext.
        with open(file_path, "rb") as src2:
            src2.seek(total - tag_len)
            tag = src2.read(tag_len)
            if len(tag) != tag_len:
                raise ValueError("Invalid RSA encrypted file (missing tag)")

            cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag), backend=default_backend())
            decryptor = cipher.decryptor()

            if output_path is None:
                if file_path.endswith(".enc"):
                    output_path = file_path[:-4] + "_decrypted"
                else:
                    output_path = file_path + "_decrypted"

            src2.seek(header_len)
            read_bytes = 0
            with open(output_path, "wb") as dst:
                while read_bytes < ciphertext_len:
                    to_read = min(CHUNK_SIZE, ciphertext_len - read_bytes)
                    chunk = src2.read(to_read)
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
                    self._logger.error(
                        "Failed to decrypt '%s' with RSA hybrid (authentication error)",
                        file_path,
                    )
                    raise
                if final_pt:
                    dst.write(final_pt)

        self._logger.info("Decrypted file '%s' with RSA hybrid", file_path)
        return output_path

    @property
    def algorithm_name(self) -> str:
        return "RSA"
