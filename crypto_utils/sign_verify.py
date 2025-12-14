from cryptography.hazmat.primitives.asymmetric import ed25519
import base64 

def signer(sign_private, message: bytes) -> bytes:
    """
    Sign a message using the provided Ed25519 private key.

    :param sign_private: Ed25519 private key for signing
    :param message: Message to be signed (in bytes)
    :return: Signature (in bytes)
    """
    signature = sign_private.sign(message)
    return signature


def verifier(sign_public, message: bytes, signature: bytes) -> bool:
    """
    Verify a signature using the provided Ed25519 public key.

    :param sign_public: Ed25519 public key for verification
    :param message: Original message (in bytes)
    :param signature: Signature to be verified (in bytes)
    :return: True if the signature is valid, False otherwise
    """
    try:
        sign_public.verify(signature, message)
        return True
    except Exception:
        return False