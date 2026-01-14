from cryptography.fernet import Fernet

class Encryptor:
    """
    Encryptor handles chunk-based encryption of files
    using symmetric encryption.
    """
    def __init__(self, key: bytes, chunk_size: int = 4096):
        self.fernet = Fernet(key)
        self.chunk_size = chunk_size

    def encrypt_file(self, input_path: str, output_path: str) -> None:
        """
        Encrypts a file in chunks and writes encrypted data to output_path.

        :param input_path: Path of the file to encrypt
        :param output_path: Path where encrypted file will be saved
        """
        with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
            while True:
                chunk = infile.read(self.chunk_size)
                if not chunk:
                    break

                encrypted_chunk = self.fernet.encrypt(chunk)
                outfile.write(encrypted_chunk)
