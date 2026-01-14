import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class KeyManager:
    """
    KeyManager handles secure key derivation using a password.It uses PBKDF2 with SHA-256 to derive encryption keys.
    """
    def __init__(self, iterations: int = 100_000):
        self.iterations = iterations

    def generate_salt(self) -> bytes:
        """
        Generates a cryptographically secure random salt.
        """
        return os.urandom(16)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a symmetric encryption key from a password and salt.

        :param password: User-provided password
        :param salt: Random salt
        :return: Derived key (base64 encoded)
        """
        password_bytes = password.encode()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )

        key = kdf.derive(password_bytes)
        return base64.urlsafe_b64encode(key)
