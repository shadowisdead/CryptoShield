"""
Secure file deletion - overwrites file with random data before deletion.
"""

import os


def secure_delete(path: str, passes: int = 3) -> bool:
    """
    Securely delete a file by overwriting with random data.
    passes: number of overwrite passes (default 3 for DoD 5220.22-M style).
    Returns True if successful.
    """
    try:
        if not os.path.isfile(path):
            return False
        size = os.path.getsize(path)
        with open(path, "wb") as f:
            for _ in range(passes):
                f.seek(0)
                written = 0
                chunk_size = 4096
                while written < size:
                    to_write = min(chunk_size, size - written)
                    f.write(os.urandom(to_write))
                    written += to_write
        os.remove(path)
        return True
    except OSError:
        return False
