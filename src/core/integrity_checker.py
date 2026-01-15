import hashlib


class IntegrityChecker:
    """
    Handles file integrity verification using SHA-256 hashing.
    """

    def __init__(self, chunk_size: int = 4096):
        self.chunk_size = chunk_size

    def generate_hash(self, file_path: str) -> str:
        """
        Generates SHA-256 hash of a file.

        :param file_path: Path to the file
        :return: Hexadecimal hash string
        """
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            while True:
                chunk = file.read(self.chunk_size)
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    def verify_integrity(self, file_path: str, expected_hash: str) -> bool:
        """
        Verifies file integrity by comparing hashes.

        :param file_path: Path to the file
        :param expected_hash: Previously generated hash
        :return: True if file is intact, False otherwise
        """
        return self.generate_hash(file_path) == expected_hash
