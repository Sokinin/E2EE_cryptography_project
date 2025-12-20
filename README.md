# E2EE Encryption Demo (socket-based)

This repository contains a minimal socket-based chat demo that demonstrates
basic end-to-end encrypted messaging using Ed25519 (signing) and X25519
(ECDH) to derive symmetric keys. Message payloads are encrypted with AES‑GCM.

Project layout (relevant files)
- `server.py` — pairing server that forwards messages between two clients.
- `client.py` — interactive client that connects to the server, performs key
	registration, derives a shared symmetric key, and sends/receives messages.
- `crypto_utils/` — crypto helpers:
	- `keygen.py` — `generate_keys()` produces Ed25519 (sign) and X25519 (enc) keys.
	- `dh_exchange.py` — derive symmetric key from X25519 private/public pair.
	- `encryption.py` — AES‑GCM encrypt/decrypt helpers.
	- `sign_verify.py` — `signer()` and `verifier()` expect Ed25519 key objects.
- `keystore/` — `simple_keystore.py` stores key blobs under `keystore/keys/`.

Quick start

1. Clone the repository and change to the project root (important):

```bash
git clone https://github.com/Sokinin/E2EE_cryptography_project.git
cd E2EE_cryptography_project
```

2. Create and activate a virtual environment, then install requirements.

Windows PowerShell

```powershell
python -m venv .e2e_venv
.\.e2e_venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS / Linux (bash)

```bash
python3 -m venv .e2e_venv
source .e2e_venv/bin/activate
pip install -r requirements.txt
```

Run the server (single terminal):

Windows / macOS / Linux

```bash
python server.py
# or on some systems: python3 server.py
```

Run a client (another terminal):

```bash
python client.py
# or on some systems: python3 client.py
```
Note: run two terminals for two clients so they can connect and communicate with each other.

Behavior notes
 - The first time a client runs it will generate a keypair (Ed25519 + X25519)
	via `crypto_utils/keygen.py` and save them using the `SimpleKeyStore` in `keystore/simple_keystore.py`.
- Clients register with `server.py` by sending base64-encoded public keys. The
	server pairs two clients who requested each other and forwards their messages.
- `sign_verify.signer()` and `verifier()` do not create keys — they accept
	Ed25519 key objects (from `generate_keys()` or loaded from the keystore).

Security note
- Persisting ephemeral private keys defeats forward secrecy. This demo stores
	long-term identity keys (Ed25519) and X25519 keys are used as the ephemeral
	key material in this simple design.

Development & tests
- To run the included tests (if present):

```powershell
pytest -q
```

Where keys are stored
- Key files are written to `keystore/keys/<username>_keys.json`. Add
	`keystore/keys/` to `.gitignore` to avoid committing private material.

If you'd like the README expanded (protocol details, handshake flow,
or code examples), tell me which section to expand.
