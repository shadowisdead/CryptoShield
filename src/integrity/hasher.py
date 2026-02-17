import hashlib

from core.logger import get_logger

class Hasher:
    def __init__(self):
        self._logger = get_logger()

    def generate_hash(self, file_path: str) -> str:
        """
        Generates SHA-256 hash of a file
        """

        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)  # Efficient chunk reading
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    def verify_hash(self, file_path: str, original_hash: str) -> bool:
        """
        Verifies file integrity by comparing hashes
        """

        current_hash = self.generate_hash(file_path)
        ok = current_hash == original_hash
        if not ok:
            self._logger.warning(
                "Integrity verification failed for '%s' (expected %s, got %s)",
                file_path,
                original_hash,
                current_hash,
            )
        return ok
