import socket
import json
import base64
import threading
import os

from crypto_utils.keygen import sign_generate_keys, en_generate_keys
from crypto_utils.encryption import encrypt_message, decrypt_message
from crypto_utils.dh_exchange import derive_symmetric_key
from crypto_utils.sign_verify import signer, verifier
from keystore.simple_keystore import SimpleKeyStore
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from dotenv import load_dotenv
load_dotenv()


def listen(sock, symmetric_key, peer_sign_public):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break

            payload = json.loads(data.decode())
            ciphertext = base64.b64decode(payload["ciphertext"])
            signature = base64.b64decode(payload["signature"])

            if not verifier(peer_sign_public, ciphertext, signature):
                print("Invalid signature")
                continue

            msg = decrypt_message(symmetric_key, payload)
            print("\n[Peer]:", msg)
            
            if msg.lower() == "bye":
                print("Peer has exited the chat.")
                break

        except (ConnectionResetError, BrokenPipeError) as e:
            print("Listener error: connection closed by peer:", e)
            try:
                sock.close()
            except Exception:
                pass
            break
        except OSError as e:
            if getattr(e, "winerror", None) == 10053:
                print("Listener error: connection aborted by local host (WinError 10053). Closing socket.")
            else:
                print("Listener OSError:", e)
            try:
                sock.close()
            except Exception:
                pass
            break
        except Exception as e:
            print("Listener unexpected error:", e)
            try:
                sock.close()
            except Exception:
                pass
            break

def run_client():
    username = input("Your name: ").strip()
    target = input("Target name: ").strip()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    
    server_ip = os.getenv("server_ip")
    server_port = int(os.getenv("server_port")) 

    sock.connect((server_ip, server_port))

    # Load or generate keys
    store = SimpleKeyStore(username)
    en_keys = en_generate_keys()

    if not os.path.exists(store.file_path):
        sign_keys = sign_generate_keys()
        store.save_keys(
            sign_private=sign_keys["sign_private"],
            sign_public=sign_keys["sign_public"],
            enc_private=en_keys["enc_private"],
            enc_public=en_keys["enc_public"]
        )
    else:
        store.load_keys()  # loads into store attributes

        store.save_keys(
            sign_private=store.sign_private,
            sign_public=store.sign_public,
            enc_private=en_keys["enc_private"],
            enc_public=en_keys["enc_public"]
        )


    # Register with server (send keys as base64)
    sock.send(json.dumps({
        "username": username,
        "target": target,
        "keys": {
            "sign_public": base64.b64encode(
                store.sign_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode(),
            "enc_public": base64.b64encode(
                store.enc_public.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode()
        }
    }).encode())

    # Receive peer public keys
    data = sock.recv(4096)
    msg = json.loads(data.decode())
    peer_keys = msg["keys"]

    # Convert peer keys from base64 to key objects
    peer_sign_public = ed25519.Ed25519PublicKey.from_public_bytes(
        base64.b64decode(peer_keys["sign_public"])
    )
    peer_enc_public = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(peer_keys["enc_public"])
    )

    # Derive symmetric key with peer
    symmetric_key = derive_symmetric_key(
        store.enc_private,
        peer_enc_public
    )

    # Start listener thread
    threading.Thread(
        target=listen,
        args=(sock, symmetric_key, peer_sign_public),
        daemon=True
    ).start()

    # Sending loop
    while True:
        try:
            text = input(" ").strip()
            if not text:
                continue
            
            if text.lower() == "bye":
                print("Exiting chat.")
                break

            encrypted = encrypt_message(symmetric_key, text)
            signature = signer(
                store.sign_private,
                base64.b64decode(encrypted["ciphertext"])
            )

            sock.send(json.dumps({
                "nonce": encrypted["nonce"],
                "ciphertext": encrypted["ciphertext"],
                "signature": base64.b64encode(signature).decode()
            }).encode())

        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print("Send error: connection closed or aborted:", e)
            try:
                sock.close()
            except Exception:
                pass
            break
        except KeyboardInterrupt:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            break

    sock.close()


if __name__ == "__main__":
    run_client()
