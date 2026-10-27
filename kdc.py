import argparse
import json
import random
import socket
import string
import threading

from aes import encrypt_text

keys = {}                      # { "Alice": "<master_key_alice>", "Bob": "<master_key_bob>" }
keys_lock = threading.Lock()
_rng = random.SystemRandom()


def gen_session_key():
    alphabet = string.ascii_letters + string.digits
    return "".join(_rng.choice(alphabet) for _ in range(16))


def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def handle(conn, addr):
    f = conn.makefile("r")
    try:
        line = f.readline()
        if not line:
            return
        req = json.loads(line)
        print(f"\n[KDC] === Langkah 1 diterima dari {addr[0]}:{addr[1]} ===")
        print(f"[KDC] {req}")
        ida, idb, n1 = req["id_a"], req["id_b"], req["n1"]

        with keys_lock:
            ka, kb = keys.get(ida), keys.get(idb)
        if ka is None or kb is None:
            print(f"[KDC] ID tidak dikenal ({ida}/{idb}) -> ditolak")
            send_json(conn, {"error": "ID tidak terdaftar di KDC"})
            return

        ks = gen_session_key()
        ticket = encrypt_text(kb, f"{ks}|{ida}")
        payload = "|".join([ks, idb, n1, ticket])
        data = encrypt_text(ka, payload)

        print(f"[KDC] Session key Ks (dibuat KDC) : {ks}")
        print(f"[KDC] Ticket E(Kb,[Ks||ID_A])      : {ticket}")
        print(f"[KDC] === Langkah 2 dikirim ke {ida} ===")
        print(f"[KDC] E(Ka,[...]) hex              : {data}")
        send_json(conn, {"step": 2, "data": data})
    except Exception as e:
        print(f"[KDC] error: {e}")
    finally:
        conn.close()


def server(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"[KDC] Listening di 0.0.0.0:{port}")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    print("Masukkan master key (ASCII, 16 karakter; kurang -> dipad '0').")
    for name in ("Alice", "Bob"):
        k = input(f"  Key {name} (Ka/Kb): ").strip()
        keys[name] = k
    threading.Thread(target=server, args=(args.port,), daemon=True).start()

    print("\nPerintah: list | setkey <ID> <key> | add <ID> <key> | quit")
    while True:
        try:
            cmd = input("KDC> ").strip().split()
        except (EOFError, KeyboardInterrupt):
            break
        if not cmd:
            continue
        if cmd[0] == "list":
            with keys_lock:
                for k, v in keys.items():
                    print(f"  {k}: {v}")
        elif cmd[0] in ("setkey", "add") and len(cmd) == 3:
            with keys_lock:
                keys[cmd[1]] = cmd[2]
            print(f"  key {cmd[1]} diubah -> {cmd[2]}")
        elif cmd[0] == "quit":
            break
        else:
            print("  perintah tidak dikenal")


if __name__ == "__main__":
    main()


# python3 kdc.py [--port 5000]