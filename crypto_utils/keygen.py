import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__),".."))  # To allow imports from parent directory

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from keystore.simple_keystore import SimpleKeyStore


def sign_generate_keys()-> dict[str, bytes]:
        # Signing keys (Ed25519)
        sign_private = ed25519.Ed25519PrivateKey.generate()
        sign_public = sign_private.public_key()
        

        return {
            "sign_private": sign_private,
            "sign_public": sign_public
        }
        
def en_generate_keys()-> dict[str, bytes]:
        # Encryption keys (X25519)
        enc_private = x25519.X25519PrivateKey.generate()
        enc_public = enc_private.public_key()
        

        return {
            "enc_private": enc_private,
            "enc_public": enc_public
        }
        