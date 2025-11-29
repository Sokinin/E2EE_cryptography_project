from cryptography.hazmat.primitives.asymmetric import x25519


'''def derive_shared_key(private: x25519.X25519PrivateKey, peer_public: x25519.X25519PublicKey) -> bytes:
    """Perform X25519 key exchange; returns raw shared secret bytes."""
    return private.exchange(peer_public)'''
def derive_shared_key(private_key, peer_public_key):
    """
        private_key: X25519PrivateKey
        peer_public_key: X25519PublicKey
        returns: bytes (shared secret)
    """
    return private_key.exchange(peer_public_key)

if __name__ == "__main__":
    from keygen import generate_x25519_keypair
    a_priv, a_pub = generate_x25519_keypair()
    b_priv, b_pub = generate_x25519_keypair()

    shared_a = derive_shared_key(a_priv, b_pub)
    shared_b = derive_shared_key(b_priv, a_pub)
    print("Shared keys equal:", shared_a == shared_b)

