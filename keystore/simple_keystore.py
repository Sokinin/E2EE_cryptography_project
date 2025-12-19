import os
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization


class SimpleKeyStore:
    """Store Ed25519 and X25519 keys securely (in JSON)."""

    def __init__(self, username):
        self.username = username
        self.file_path = f"keystore/keys/{username}_keys.json"
        os.makedirs("keystore/keys", exist_ok=True)
        

    def save_keys(self,sign_private=None,sign_public=None,enc_private=None,enc_public=None):
        self.sign_private = sign_private
        self.sign_public = sign_public
        self.enc_private = enc_private
        self.enc_public = enc_public
        
        
        data = {
            "sign_private": b64encode(self.sign_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode(),

            "sign_public": b64encode(self.sign_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode(),

            "enc_private": b64encode(self.enc_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )).decode(),

            "enc_public": b64encode(self.enc_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )).decode(),
        }

        with open(self.file_path, "w") as f:
            json.dump(data, f, indent=2)

    def load_keys(self):
        with open(self.file_path, "r") as f:
            data = json.load(f)

        self.sign_private = ed25519.Ed25519PrivateKey.from_private_bytes(
            b64decode(data["sign_private"])
        )
        self.sign_public = ed25519.Ed25519PublicKey.from_public_bytes(
            b64decode(data["sign_public"])
        )
        self.enc_private = x25519.X25519PrivateKey.from_private_bytes(
            b64decode(data["enc_private"])
        )
        self.enc_public = x25519.X25519PublicKey.from_public_bytes(
            b64decode(data["enc_public"])
        )
        
    


