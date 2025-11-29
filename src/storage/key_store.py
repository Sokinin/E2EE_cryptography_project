import os
from typing import Optional


def store_encrypted_key(path: str, data: bytes):
    """Store encrypted private key bytes to disk (simple file storage)."""
    with open(path, "wb") as f:
        f.write(data)


def load_encrypted_key(path: str) -> Optional[bytes]:
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()
