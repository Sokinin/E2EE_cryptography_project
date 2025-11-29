from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization

'''def generate_x25519_keypair():
    """Return (private_key, public_key) for X25519"""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def generate_ed25519_keypair():
    """Return (private_key, public_key) for Ed25519"""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )'''
    
import os
from typing import NamedTuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

class KeyPair(NamedTuple):
    """Container for X25519 and Ed25519 key pairs"""
    x25519_private: x25519.X25519PrivateKey
    x25519_public: x25519.X25519PublicKey
    ed25519_private: ed25519.Ed25519PrivateKey
    ed25519_public: ed25519.Ed25519PublicKey

def generate_keypair() -> KeyPair:
    """
    Generate a new X25519 key pair for key exchange 
    and Ed25519 key pair for signatures
    
    Returns:
        KeyPair: Container with both key pairs
    """
    # Generate X25519 keys for key exchange
    x25519_private = x25519.X25519PrivateKey.generate()
    x25519_public = x25519_private.public_key()
    
    # Generate Ed25519 keys for signatures
    ed25519_private = ed25519.Ed25519PrivateKey.generate()
    ed25519_public = ed25519_private.public_key()
    
    return KeyPair(
        x25519_private=x25519_private,
        x25519_public=x25519_public,
        ed25519_private=ed25519_private,
        ed25519_public=ed25519_public
    )

def public_key_to_bytes(public_key) -> bytes:
    """Convert public key to bytes for storage/transmission"""
    if isinstance(public_key, x25519.X25519PublicKey):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        raise ValueError("Unsupported key type")

def private_key_to_bytes(private_key, password: bytes = None) -> bytes:
    """Convert private key to bytes (optionally encrypted)"""
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()
    
    if isinstance(private_key, x25519.X25519PrivateKey):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    else:
        raise ValueError("Unsupported key type")
