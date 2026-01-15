from cryptography.fernet import Fernet, InvalidToken

class Decryptor:
    """
    Decryptor handles chunk-based decryption of encrypted files.
    """

    def __init__(self, key: bytes, chunk_size: int = 4096):
        self.fernet = Fernet(key)
        self.chunk_size = chunk_size

    def decrypt_file(self, input_path: str, output_path: str) -> bool:
        """
        Decrypts an encrypted file in chunks.

        :param input_path: Path of encrypted file
        :param output_path: Path where decrypted file will be saved
        :return: True if successful, False if decryption fails
        """
        try:
            with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
                while True:
                    chunk = infile.read(self.chunk_size)
                    if not chunk:
                        break

                    decrypted_chunk = self.fernet.decrypt(chunk)
                    outfile.write(decrypted_chunk)

            return True

        except InvalidToken:
            # Wrong password or corrupted file
            return False
