from src.protocol import handshake
from src.crypto import keygen


def test_handshake_derives_shared():
    a_xpriv, a_xpub = keygen.generate_x25519_keypair()
    a_epriv, a_epub = keygen.generate_ed25519_keypair()
    b_xpriv, b_xpub = keygen.generate_x25519_keypair()
    b_epriv, b_epub = keygen.generate_ed25519_keypair()

    res_a = handshake.perform_handshake(a_xpriv, a_epriv, b_xpub, b_epub)
    res_b = handshake.perform_handshake(b_xpriv, b_epriv, a_xpub, a_epub)

    assert res_a["shared"] and res_b["shared"]
    # raw shared secrets should be equal
    assert res_a["shared"] == res_b["shared"]
