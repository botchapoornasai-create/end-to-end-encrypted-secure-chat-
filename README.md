# end-to-end-encrypted-secure-chat-
# Secure Chat App (E2EE) - Reference Implementation

## Requirements
- Python 3.9+
- pip install -r server/requirements.txt
- pip install -r client/requirements.txt

server/requirements.txt:
Flask
Flask-SocketIO
eventlet
cryptography
requests
python-socketio

client/requirements.txt:
python-socketio
cryptography
requests

## Start server
cd secure-chat-e2ee/server
python app.py

Server listens on http://0.0.0.0:5000

## Run client (two terminals for two users)
cd secure-chat-e2ee/client
python client.py alice
python client.py bob

## Example flow
- Start server.
- Start `python client.py alice`. The client will generate RSA keypair and register public key with server.
- Start `python client.py bob`. Bob registers his public key.
- In Alice client: use `/list` to see users, then `/to bob` to start messaging Bob. Type messages; each message is encrypted with AES and AES key encrypted with Bob's RSA public key.
- Bob's client will receive message events and decrypt them locally.

## Where logs are stored?
Server saves encrypted messages to `server/data/logs.json`. These entries contain only ciphertext and the RSA-encrypted AES key — server cannot decrypt them unless it compromises a recipient's private key.

## Security notes
- This is a reference prototype. Production systems must handle:
  - Authentication & account control (prevent impersonation of username during register).
  - TLS (HTTPS/WSS) for network transport — use TLS in production to avoid MITM on the transport.
  - Secure storage of private keys on clients (use OS key stores or hardware tokens).
  - Proper rotation & revocation of keys.
  - Message metadata leakage: server still learns sender, recipient, time, message size.
  - Replay protection, message ordering, forward secrecy enhancements (e.g., use ephemeral Diffie-Hellman per message).
