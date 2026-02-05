"""
Digital signatures for encrypted files - sign file hashes for integrity verification.
"""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey #type: ignore
from cryptography.hazmat.primitives import serialization #type: ignore
from cryptography.hazmat.backends import default_backend #type: ignore
import base64
import os


class DigitalSigner:
    """Create and verify digital signatures of file hashes."""

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate Ed25519 keypair. Returns (private_pem, public_pem)."""
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        priv_pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv_pem, pub_pem

    @staticmethod
    def sign_hash(private_key_pem: bytes, hash_hex: str) -> str:
        """Sign a hash string. Returns base64-encoded signature."""
        private = serialization.load_pem_private_key(
            private_key_pem, password=None, backend=default_backend()
        )
        sig = private.sign(hash_hex.encode("utf-8"))
        return base64.b64encode(sig).decode("ascii")

    @staticmethod
    def verify_signature(public_key_pem: bytes, hash_hex: str, signature_b64: str) -> bool:
        """Verify a signature. Returns True if valid."""
        try:
            public = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )
            sig = base64.b64decode(signature_b64)
            public.verify(sig, hash_hex.encode("utf-8"))
            return True
        except Exception:
            return False
