from ..crypto import keygen, sign_verify, dh_exchange


def perform_handshake(initiator_priv_x25519, initiator_priv_ed25519, responder_pub_x25519, responder_pub_ed25519):
    """Simple illustrative handshake: derive shared secret via X25519 and sign handshake transcript."""
    # derive shared secret
    shared = dh_exchange.derive_shared_key(initiator_priv_x25519, responder_pub_x25519)
    # sign the shared secret to authenticate
    signature = sign_verify.sign_message(initiator_priv_ed25519, shared)
    return {"shared": shared, "signature": signature}
