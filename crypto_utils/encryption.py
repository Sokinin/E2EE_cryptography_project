import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- AES-GCM Encryption ---
def encrypt_message(key, message):
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, message.encode(), None)
    return {"nonce": b64encode(nonce).decode(), "ciphertext": b64encode(ciphertext).decode()}

def decrypt_message(key, encrypted):
    aes = AESGCM(key)
    nonce = b64decode(encrypted["nonce"])
    ciphertext = b64decode(encrypted["ciphertext"])
    return aes.decrypt(nonce, ciphertext, None).decode()
