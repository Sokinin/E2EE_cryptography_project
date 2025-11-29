from cryptography.hazmat.primitives.asymmetric import ed25519


def sign_message(private: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private.sign(message)


def verify_signature(public: ed25519.Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public.verify(signature, message)
        return True
    except Exception:
        return False
