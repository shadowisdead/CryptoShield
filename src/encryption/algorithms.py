"""
CryptoShield - Multi-Algorithm Encryption Support
Supports AES-256-GCM, ChaCha20-Poly1305, and RSA (hybrid with AES)
"""

from .aes_engine import AESEngine
from .chacha_engine import ChaChaEngine
from .rsa_engine import RSAEngine
from .base import EncryptionAlgorithm

# Algorithm registry: name -> (encryptor_class, decryptor_method)
ALGORITHMS = {
    "AES-256": AESEngine,
    "ChaCha20": ChaChaEngine,
    "RSA": RSAEngine,
}


def get_algorithm(name: str) -> type[EncryptionAlgorithm]:
    """Get encryption engine class by name."""
    if name not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {name}. Choose from {list(ALGORITHMS.keys())}")
    return ALGORITHMS[name]
