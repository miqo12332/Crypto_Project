from flask import Flask, request, jsonify, render_template
import secrets, hmac, hashlib, json, os, time

app = Flask(__name__)

MASTER_KEY_FILE = "master.key"
CLIENTS_FILE = "clients.json"
MESSAGES_FILE = "messages.json"

def load_master_key():
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            return bytes.fromhex(f.read().decode("utf-8"))
    key = secrets.token_bytes(32)
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(key.hex().encode("utf-8"))
    return key

def load_clients():
    if os.path.exists(CLIENTS_FILE):
        with open(CLIENTS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_clients(c):
    with open(CLIENTS_FILE, "w") as f:
        json.dump(c, f, indent=4)

def load_messages():
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, "r") as f:
            return json.load(f)
    return {}

def save_messages():
    with open(MESSAGES_FILE, "w") as f:
        json.dump(MESSAGES, f, indent=4)

MASTER_KEY = load_master_key()
clients = load_clients()
MESSAGES = load_messages()

def derive_long_term_key(cid):
    return hmac.new(MASTER_KEY, cid.encode(), hashlib.sha256).digest()


def describe_long_term_derivation(cid, key_bytes):
    return {
        "algorithm": "HMAC-SHA256(master_key, client_id)",
        "client_id": cid,
        "client_id_hex": cid.encode().hex(),
        "master_key_hex": MASTER_KEY.hex(),
        "hmac_digest_hex": key_bytes.hex(),
    }

def derive_shared_key(a, b):
    Ka = bytes.fromhex(clients[a])
    Kb = bytes.fromhex(clients[b])
    if a < b:
        msg = Ka + Kb + f"{a}|{b}".encode()
    else:
        msg = Kb + Ka + f"{b}|{a}".encode()
    digest = hmac.new(MASTER_KEY, msg, hashlib.sha256).digest()
    return digest


def describe_shared_derivation(a, b, digest):
    Ka = bytes.fromhex(clients[a])
    Kb = bytes.fromhex(clients[b])
    ordered = (a, b) if a < b else (b, a)
    msg = (Ka if ordered[0] == a else Kb) + (Kb if ordered[1] == b else Ka) + f"{ordered[0]}|{ordered[1]}".encode()
    return {
        "algorithm": "HMAC-SHA256(master_key, Ka||Kb||names)",
        "participants": ordered,
        "Ka_hex": Ka.hex(),
        "Kb_hex": Kb.hex(),
        "concat_hex": msg.hex(),
        "label": f"{ordered[0]}|{ordered[1]}",
        "master_key_hex": MASTER_KEY.hex(),
        "hmac_digest_hex": digest.hex(),
    }

@app.route("/")
def ui():
    return render_template("chat.html")

@app.route("/register", methods=["POST"])
def register():
    cid = request.json.get("client_id")
    if not cid:
        return jsonify({"error": "missing id"}), 400
    if cid in clients:
        return jsonify({"error": "exists"}), 400
    key = derive_long_term_key(cid)
    clients[cid] = key.hex()
    save_clients(clients)
    return jsonify({
        "client_id": cid,
        "long_term_key": key.hex(),
        "derivation": describe_long_term_derivation(cid, key)
    })

@app.route("/clients", methods=["GET"])
def list_clients():
    return jsonify(sorted(list(clients.keys())))

@app.route("/shared-key", methods=["POST"])
def shared():
    a = request.json["client_a"]
    b = request.json["client_b"]
    if a not in clients or b not in clients:
        return jsonify({"error": "unknown"}), 404
    digest = derive_shared_key(a, b)
    return jsonify({
        "shared_key": digest.hex(),
        "derivation": describe_shared_derivation(a, b, digest)
    })

@app.route("/encrypt", methods=["POST"])
def encrypt_api():
    from crypto_utils import aes_encrypt
    key = request.json["key"]
    msg = request.json["message"]
    return jsonify(aes_encrypt(key, msg))

@app.route("/decrypt", methods=["POST"])
def decrypt_api():
    from crypto_utils import aes_decrypt
    key = request.json["key"]
    ct = request.json["ciphertext"]
    return jsonify(aes_decrypt(key, ct))

@app.route("/send", methods=["POST"])
def send_msg():
    s = request.json["sender"]
    r = request.json["receiver"]
    ct = request.json["ciphertext"]
    if r not in MESSAGES:
        MESSAGES[r] = []
    MESSAGES[r].append({
        "id": secrets.token_hex(4),
        "from": s,
        "ciphertext": ct,
        "timestamp": time.time(),
        "status": "unread"
    })
    save_messages()
    return jsonify({"status": "stored"})

@app.route("/inbox/<user>", methods=["GET"])
def inbox(user):
    if user not in MESSAGES:
        return jsonify([])
    msgs = MESSAGES[user]
    for m in msgs:
        m["status"] = "read"
    save_messages()
    return jsonify(msgs)

@app.route("/clear-messages", methods=["POST"])
def clear_messages():
    global MESSAGES
    MESSAGES = {}
    save_messages()
    return jsonify({"status": "all messages deleted"})

if __name__ == "__main__":
    app.run(port=5000, debug=True)
