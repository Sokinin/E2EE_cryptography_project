from src.crypto import encrypt, decrypt
import os


def test_encrypt_decrypt():
    key = os.urandom(32)
    pt = b"hello world"
    out = encrypt.aead_encrypt(key, pt)
    assert "nonce" in out and "ciphertext" in out
    pt2 = decrypt.aead_decrypt(key, out["nonce"], out["ciphertext"])
    assert pt2 == pt
