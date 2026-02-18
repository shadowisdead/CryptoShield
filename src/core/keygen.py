"""
Secure key and password generation utilities.
"""

import secrets
import string


def generate_random_password(
    length: int = 24,
    include_uppercase: bool = True,
    include_lowercase: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True,
) -> str:
    """Generate a cryptographically secure random password."""
    chars = ""
    if include_uppercase:
        chars += string.ascii_uppercase
    if include_lowercase:
        chars += string.ascii_lowercase
    if include_digits:
        chars += string.digits
    if include_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"
    if not chars:
        chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def generate_random_key(num_bytes: int = 32) -> bytes:
    """Generate cryptographically secure random bytes (e.g. for encryption keys)."""
    return secrets.token_bytes(num_bytes)


def generate_hex_key(num_bytes: int = 32) -> str:
    """Generate random key as hex string."""
    return secrets.token_hex(num_bytes)
