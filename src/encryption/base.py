"""
Base class for encryption engines - defines the interface.
"""

from abc import ABC, abstractmethod
from typing import Callable, Optional


class EncryptionAlgorithm(ABC):
    """Abstract base for all encryption algorithms."""

    @abstractmethod
    def encrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        delete_original: bool = False,
    ) -> str:
        """Encrypt a file. Returns path to encrypted file."""
        pass

    @abstractmethod
    def decrypt_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> str:
        """Decrypt a file. Returns path to decrypted file."""
        pass

    @property
    @abstractmethod
    def algorithm_name(self) -> str:
        """Human-readable algorithm name."""
        pass
