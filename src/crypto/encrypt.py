import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> dict:
    """Encrypt with AES-256-GCM. Returns dict: {nonce, ct, tag} where values are bytes."""
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    nonce = os.urandom(12)
    aead = AESGCM(key)
    ct = aead.encrypt(nonce, plaintext, aad)
    return {"nonce": nonce, "ciphertext": ct}
