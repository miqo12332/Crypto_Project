import sys, requests, time
from crypto_utils import aes_encrypt, aes_decrypt

SERVER_URL = "http://127.0.0.1:5000"

def reg(cid):
    print(requests.post(f"{SERVER_URL}/register", json={"client_id": cid}).json())

def shared(a, b):
    return requests.post(f"{SERVER_URL}/shared-key",
        json={"client_a": a, "client_b": b}).json()["shared_key"]

def send_msg(s, r, msg):
    key = shared(s, r)
    ct = aes_encrypt(key, msg)
    print(requests.post(f"{SERVER_URL}/send",
        json={"sender": s, "receiver": r, "ciphertext": ct}).json())

def inbox(u):
    msgs = requests.get(f"{SERVER_URL}/inbox/{u}").json()
    for m in msgs:
        key = shared(u, m["from"])
        pt = aes_decrypt(key, m["ciphertext"])
        t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m["timestamp"]))
        print(f"ID: {m['id']}")
        print(f"Time: {t}")
        print(f"From: {m['from']}")
        print(f"Encrypted: {m['ciphertext']}")
        print(f"Decrypted: {pt}")
        print(f"Status: {m['status']}")
        print("-" * 40)

def usage():
    print("python3 client.py register <id>")
    print("python3 client.py shared <a> <b>")
    print("python3 client.py send <sender> <receiver> <msg>")
    print("python3 client.py inbox <user>")

if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "register":
        reg(sys.argv[2])
    elif cmd == "shared":
        print(shared(sys.argv[2], sys.argv[3]))
    elif cmd == "send":
        send_msg(sys.argv[2], sys.argv[3], " ".join(sys.argv[4:]))
    elif cmd == "inbox":
        inbox(sys.argv[2])
    else:
        usage()
