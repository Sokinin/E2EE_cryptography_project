from src.crypto import sign_verify, keygen


def test_sign_and_verify():
    priv, pub = keygen.generate_ed25519_keypair()
    m = b"message"
    sig = sign_verify.sign_message(priv, m)
    assert sign_verify.verify_signature(pub, m, sig)
