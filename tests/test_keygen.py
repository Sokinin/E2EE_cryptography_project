from src.crypto import keygen


def test_generate_keys():
    xpriv, xpub = keygen.generate_x25519_keypair()
    epriv, epub = keygen.generate_ed25519_keypair()
    assert xpriv is not None and xpub is not None
    assert epriv is not None and epub is not None
