from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import constant_time
import os


def derive_key_from_password(password: bytes, salt: bytes = None, iterations: int = 200000, length: int = 32) -> tuple:
    """Return (key, salt). Uses PBKDF2-HMAC-SHA256 by default."""
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
    )
    key = kdf.derive(password)
    return key, salt
