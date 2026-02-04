import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC #type: ignore
from cryptography.hazmat.primitives import hashes #type: ignore
from cryptography.hazmat.backends import default_backend #type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes #type: ignore
from cryptography.hazmat.primitives import padding #type: ignore

class Decryptor:
    def __init__(self, password: str):
        self.password = password.encode()
        self.backend = default_backend()

    def generate_key(self, salt: bytes) -> bytes:
        """
        Generate the same key used for encryption
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(self.password)

    def decrypt_file(self, encrypted_file_path: str) -> str:
        """
        Decrypts AES encrypted file
        Returns decrypted file path
        """

        with open(encrypted_file_path, "rb") as f:
            file_data = f.read()

        # Extract salt, IV, encrypted content
        salt = file_data[:16]
        iv = file_data[16:32]
        encrypted_data = file_data[32:]

        key = self.generate_key(salt)

        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )

        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()

        # Restore original file name
        if encrypted_file_path.endswith(".enc"):
            output_path = encrypted_file_path.replace(".enc", "_decrypted")
        else:
            output_path = encrypted_file_path + "_decrypted"

        with open(output_path, "wb") as f:
            f.write(original_data)

        return output_path
