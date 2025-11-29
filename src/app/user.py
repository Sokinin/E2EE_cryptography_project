from ..crypto import keygen

class User:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.x25519_priv, self.x25519_pub = keygen.generate_x25519_keypair()
        self.ed25519_priv, self.ed25519_pub = keygen.generate_ed25519_keypair()

    def identity(self):
        return self.user_id
