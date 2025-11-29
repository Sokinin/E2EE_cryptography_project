from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = None) -> bytes:
    aead = AESGCM(key)
    return aead.decrypt(nonce, ciphertext, aad)
