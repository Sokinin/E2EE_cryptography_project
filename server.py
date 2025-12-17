import socket
import json
import threading
import os
from dotenv import load_dotenv
load_dotenv()

waiting = {}      # username -> (socket, target, keys)
paired = {}       # socket -> peer_socket


def forward(src, dst):
    while True:
        try:
            data = src.recv(4096)
            if not data:
                break
            dst.send(data)
        except:
            break


def handle_client(sock):
    try:
        # Receive registration
        data = sock.recv(4096)
        reg = json.loads(data.decode())

        username = reg["username"]
        target = reg["target"]
        keys = reg["keys"]

        print(f"[+] {username} wants to chat with {target}")

        waiting[username] = (sock, target, keys)

        # Check if target already waiting for this user
        if target in waiting:
            peer_sock, peer_target, peer_keys = waiting[target]

            if peer_target == username:
                print(f"[✓] Pairing {username} <-> {target}")

                # Send peer public keys
                sock.send(json.dumps({
                    "type": "peer_keys",
                    "keys": peer_keys
                }).encode())

                peer_sock.send(json.dumps({
                    "type": "peer_keys",
                    "keys": keys
                }).encode())

                # Start forwarding threads
                threading.Thread(
                    target=forward,
                    args=(sock, peer_sock),
                    daemon=True
                ).start()

                threading.Thread(
                    target=forward,
                    args=(peer_sock, sock),
                    daemon=True
                ).start()

                del waiting[username]
                del waiting[target]

    except Exception as e:
        print("Server error:", e)


def run_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = os.getenv("server_ip")
    port = int(os.getenv("server_port"))
    
    server.bind((ip, port))
    server.listen(2)
    print(f"Listening on {ip}:{port}...")

    try:
        while True:
            sock, addr = server.accept()
            threading.Thread(
                target=handle_client,
                args=(sock,),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    finally:
        server.close()


if __name__ == "__main__":
    run_server()
