import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import base64

class Encryptor:
    def __init__(self, password: str):
        self.password = password.encode()
        self.backend = default_backend()

    def generate_key(self, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,   # 256 bit key
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def encrypt_file(self, file_path: str) -> str:
        """
        Encrypts a file using AES-CBC
        Returns encrypted file path
        """

        # Generate random salt & IV
        salt = os.urandom(16)
        iv = os.urandom(16)

        key = self.generate_key(salt)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )

        encryptor = cipher.encryptor()

        # Read file data
        with open(file_path, "rb") as f:
            data = f.read()

        # Padding (AES requires blocks of 16 bytes)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save encrypted file
        encrypted_file_path = file_path + ".enc"

        with open(encrypted_file_path, "wb") as f:
            f.write(salt + iv + encrypted_data)

        return encrypted_file_path
