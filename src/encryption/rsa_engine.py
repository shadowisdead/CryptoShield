"""
RSA hybrid encryption: AES-256-GCM for file data, RSA for the session key.
Requires RSA keypair generation (user provides or we generate).
"""

import os
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM #type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding #type: ignore
from cryptography.hazmat.primitives import serialization, hashes #type: ignore
from cryptography.hazmat.backends import default_backend #type: ignore

from core.secure_delete import secure_delete
from .base import EncryptionAlgorithm


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
        aesgcm = AESGCM(session_key)

        with open(file_path, "rb") as f:
            data = f.read()

        total = len(data)
        self._report_progress(progress_callback, total // 2, total)
        encrypted_data = aesgcm.encrypt(nonce, data, None)
        self._report_progress(progress_callback, total, total)

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
        with open(out, "wb") as f:
            f.write(bytes([self.VERSION, self.ALGO_ID]))
            f.write(len(encrypted_key).to_bytes(2, "big"))
            f.write(encrypted_key)
            f.write(encrypted_data)

        if delete_original:
            secure_delete(file_path)

        return out

    def decrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        if not self._private_key:
            raise ValueError("RSA private key required for decryption.")

        with open(file_path, "rb") as f:
            raw = f.read()

        if len(raw) < 4:
            raise ValueError("Invalid RSA encrypted file")

        ver, algo = raw[0], raw[1]
        if ver != 1 or algo != self.ALGO_ID:
            raise ValueError("File was not encrypted with RSA hybrid")

        key_len = int.from_bytes(raw[2:4], "big")
        encrypted_key = raw[4 : 4 + key_len]
        encrypted_data = raw[4 + key_len :]

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

        aesgcm = AESGCM(session_key)
        data = aesgcm.decrypt(nonce, encrypted_data, None)

        total = len(raw)
        self._report_progress(progress_callback, total, total)

        if output_path is None:
            if file_path.endswith(".enc"):
                output_path = file_path[:-4] + "_decrypted"
            else:
                output_path = file_path + "_decrypted"

        with open(output_path, "wb") as f:
            f.write(data)
        return output_path

    @property
    def algorithm_name(self) -> str:
        return "RSA"
