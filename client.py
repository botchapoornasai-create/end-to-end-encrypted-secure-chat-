# client/client.py
import os
import sys
import json
import base64
import time
import requests
from pathlib import Path
from getpass import getpass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import socketio

# Config
SERVER_BASE = os.environ.get("SC_SERVER", "http://localhost:5000")
KEYS_DIR = Path(__file__).resolve().parent / "keys"
KEYS_DIR.mkdir(parents=True, exist_ok=True)

def gen_or_load_rsa(username, key_size=2048):
    priv_path = KEYS_DIR / f"{username}_priv.pem"
    pub_path = KEYS_DIR / f"{username}_pub.pem"
    if priv_path.exists() and pub_path.exists():
        priv_pem = priv_path.read_bytes()
        pub_pem = pub_path.read_bytes()
        private_key = serialization.load_pem_private_key(priv_pem, password=None)
        public_key = serialization.load_pem_public_key(pub_pem)
        return private_key, public_key
    # generate new
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    # write to files
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_path.write_bytes(priv_pem)
    pub_path.write_bytes(pub_pem)
    print(f"Generated RSA keypair for {username}, saved to {KEYS_DIR}")
    return private_key, public_key

def register_public_key(username, public_key_pem):
    url = SERVER_BASE.rstrip("/") + "/register"
    resp = requests.post(url, json={"username": username, "public_key_pem": public_key_pem.decode()})
    resp.raise_for_status()
    return resp.json()

def fetch_public_key(username):
    url = SERVER_BASE.rstrip("/") + f"/public_key/{username}"
    resp = requests.get(url)
    if resp.status_code != 200:
        raise ValueError(f"Could not fetch public key for {username}: {resp.status_code} {resp.text}")
    return resp.json()["public_key_pem"].encode()

def rsa_encrypt(public_key, plaintext_bytes):
    return public_key.encrypt(
        plaintext_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def aes_encrypt(aes_key, plaintext_bytes, associated_data=None):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
    return nonce, ct

def aes_decrypt(aes_key, nonce, ciphertext, associated_data=None):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

# --- SocketIO client and interactive loop ---
sio = socketio.Client()

def run_client(username):
    private_key, public_key = gen_or_load_rsa(username)
    # register public key
    pub_pem = public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        register_public_key(username, pub_pem)
        print("Registered public key with server.")
    except Exception as e:
        print("Warning: could not register public key:", e)

    @sio.event
    def connect():
        print("Connected to server.")
        sio.emit('join', {'username': username})

    @sio.event
    def disconnect():
        print("Disconnected from server.")

    @sio.on('message')
    def on_message(data):
        # Received encrypted log entry
        # data has encrypted_key_b64, ciphertext_b64, nonce_b64, from, to, timestamp
        try:
            enc_key_b64 = data['encrypted_key_b64']
            ciphertext_b64 = data['ciphertext_b64']
            nonce_b64 = data['nonce_b64']
            sender = data.get('from')
            enc_key = base64.b64decode(enc_key_b64)
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            # decrypt AES key with our private RSA
            aes_key = rsa_decrypt(private_key, enc_key)
            plaintext = aes_decrypt(aes_key, nonce, ciphertext)
            print(f"\n[{data.get('timestamp')}] <{sender}>: {plaintext.decode()}\n> ", end="", flush=True)
        except Exception as e:
            print("Failed to decrypt incoming message:", e)

    # connect to socketio
    sio.connect(SERVER_BASE, transports=['websocket'])
    print("Type: /list to list users, /to <user> to start a direct message, /exit to quit.")
    try:
        while True:
            cmd = input("> ").strip()
            if not cmd:
                continue
            if cmd == "/exit":
                break
            if cmd == "/list":
                try:
                    resp = requests.get(SERVER_BASE.rstrip("/") + "/users")
                    users = resp.json().get("users", [])
                    print("Users:", users)
                except Exception as e:
                    print("Could not list users:", e)
                continue
            if cmd.startswith("/to "):
                _, target = cmd.split(" ", 1)
                target = target.strip()
                if not target:
                    print("Specify recipient: /to username")
                    continue
                print(f"Messaging {target}. Type message and Enter. /back to stop.")
                while True:
                    msg = input(f"{username} -> {target}: ")
                    if msg.strip() == "/back":
                        break
                    # encrypt with AES, then RSA-encrypt AES key to recipient's public key
                    try:
                        target_pub_pem = fetch_public_key(target)
                    except Exception as e:
                        print("Could not fetch target public key:", e)
                        break
                    target_public_key = serialization.load_pem_public_key(target_pub_pem)
                    aes_key = AESGCM.generate_key(bit_length=256)
                    nonce, ciphertext = aes_encrypt(aes_key, msg.encode())
                    encrypted_key = rsa_encrypt(target_public_key, aes_key)
                    payload = {
                        "from": username,
                        "to": target,
                        "encrypted_key_b64": base64.b64encode(encrypted_key).decode(),
                        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
                        "nonce_b64": base64.b64encode(nonce).decode(),
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    }
                    # emit via socket
                    sio.emit('send_message', payload)
                continue
            # otherwise, plain typing to broadcast? disallowed in E2EE model; prompt usage
            print("Unknown command. Use /list, /to <user>, /exit")
    except KeyboardInterrupt:
        print("Exiting...")
    finally:
        sio.disconnect()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py <username>")
        sys.exit(1)
    username = sys.argv[1]
    run_client(username)

