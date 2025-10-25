# server/app.py
import os
import json
import base64
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERS_FILE = DATA_DIR / "users.json"
LOGS_FILE = DATA_DIR / "logs.json"

# ensure files exist
if not USERS_FILE.exists():
    USERS_FILE.write_text(json.dumps({}))
if not LOGS_FILE.exists():
    LOGS_FILE.write_text(json.dumps([]))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'  # change for production
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# --- Helpers for persistence ---
def load_users():
    return json.loads(USERS_FILE.read_text())

def save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2))

def append_log(entry):
    logs = json.loads(LOGS_FILE.read_text())
    logs.append(entry)
    LOGS_FILE.write_text(json.dumps(logs, indent=2))

# --- REST endpoints ---

@app.route('/register', methods=['POST'])
def register():
    """
    Body JSON: { "username": "alice", "public_key_pem": "-----BEGIN PUBLIC KEY-----..." }
    """
    data = request.get_json()
    username = data.get("username")
    public_key_pem = data.get("public_key_pem")
    if not username or not public_key_pem:
        return jsonify({"error": "username and public_key_pem required"}), 400
    users = load_users()
    users[username] = public_key_pem
    save_users(users)
    return jsonify({"status": "ok"}), 200

@app.route('/public_key/<username>', methods=['GET'])
def get_public_key(username):
    users = load_users()
    pk = users.get(username)
    if not pk:
        return jsonify({"error": "user not found"}), 404
    return jsonify({"username": username, "public_key_pem": pk}), 200

@app.route('/users', methods=['GET'])
def list_users():
    users = load_users()
    return jsonify({"users": list(users.keys())}), 200

# --- SocketIO events ---
# We'll use rooms named after username to send direct messages

@socketio.on('connect')
def handle_connect():
    print("Client connected:", request.sid)
    emit('connected', {'sid': request.sid})

@socketio.on('join')
def handle_join(data):
    # data: {"username": "alice"}
    username = data.get('username')
    if not username:
        emit('error', {'message': 'username required to join'})
        return
    join_room(username)
    print(f"SID {request.sid} joined room {username}")
    emit('joined', {'username': username})

@socketio.on('leave')
def handle_leave(data):
    username = data.get('username')
    leave_room(username)
    emit('left', {'username': username})

@socketio.on('send_message')
def handle_send_message(payload):
    """
    Payload expected:
    {
      "from": "alice",
      "to": "bob",
      "encrypted_key_b64": "<RSA-encrypted AES key, base64>",
      "ciphertext_b64": "<AES-GCM ciphertext, base64>",
      "nonce_b64": "<AES-GCM nonce, base64>",
      "timestamp": "<optional ISO timestamp>",
    }
    """
    required = ["from", "to", "encrypted_key_b64", "ciphertext_b64", "nonce_b64"]
    if not all(k in payload for k in required):
        emit('error', {'message': 'missing fields'})
        return

    # store log (server stores payload as-is; server cannot decrypt the message)
    log_entry = {
        "from": payload["from"],
        "to": payload["to"],
        "encrypted_key_b64": payload["encrypted_key_b64"],
        "ciphertext_b64": payload["ciphertext_b64"],
        "nonce_b64": payload["nonce_b64"],
        "timestamp": payload.get("timestamp") or datetime.utcnow().isoformat() + "Z"
    }
    append_log(log_entry)

    # forward the message to recipient's room
    recipient = payload["to"]
    socketio.emit('message', log_entry, room=recipient)
    # also optionally echo to sender's room for UI
    socketio.emit('message_sent', {"status": "delivered", "to": recipient}, room=payload["from"])

if __name__ == "__main__":
    print("Starting Secure Chat Server on http://0.0.0.0:5000")
    socketio.run(app, host="0.0.0.0", port=5000)

