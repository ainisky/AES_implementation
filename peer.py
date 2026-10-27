import argparse
import json
import random
import socket
import threading

from aes import encrypt_text, decrypt_text

_rng = random.SystemRandom()


def send_json(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())


def recv_json(f):
    line = f.readline()
    if not line:
        raise ConnectionError("koneksi ditutup")
    return json.loads(line)


class Peer:
    def __init__(self, name, key, kdc_addr, port):
        self.name = name
        self.key = key              # kunci master milik sendiri (Ka / Kb)
        self.kdc = kdc_addr
        self.port = port
        self.sessions = {}          # nama_lawan -> {"sock":..., "ks":...}

    # ------------------------------------------------------------ listener (sisi B)
    def listen(self):
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", self.port))
        s.listen(5)
        print(f"[{self.name}] Listening di 0.0.0.0:{self.port}")
        while True:
            c, a = s.accept()
            threading.Thread(target=self.handle_incoming, args=(c, a), daemon=True).start()

    def handle_incoming(self, conn, addr):
        f = conn.makefile("r")
        try:
            m3 = recv_json(f)
            print(f"\n[{self.name}] === Langkah 3 diterima dari {addr[0]} ===")
            print(f"[{self.name}] Ticket (hex): {m3['ticket']}")
            plain = decrypt_text(self.key, m3["ticket"])
            ks, ida = plain.split("|", 1)
            print(f"[{self.name}] Dekripsi ticket -> Ks={ks}, ID_A={ida}")

            n2 = _rng.randint(10**7, 10**8 - 1)
            c4 = encrypt_text(ks, str(n2))
            print(f"[{self.name}] === Langkah 4 dikirim: N2={n2}, E(Ks,N2)={c4}")
            send_json(conn, {"step": 4, "data": c4})

            m5 = recv_json(f)
            print(f"[{self.name}] === Langkah 5 diterima: {m5['data']}")
            if int(decrypt_text(ks, m5["data"])) != n2 - 1:
                raise ValueError("verifikasi N2 gagal")
            send_json(conn, {"status": "ok"})
            print(f"[{self.name}] Autentikasi {ida} BERHASIL. Sesi aman siap.")
            self.sessions[ida] = {"sock": conn, "ks": ks}
            self.recv_loop(ida, f, ks)
        except Exception as e:
            print(f"\n[{self.name}] Gagal handshake: {e}")
            try:
                send_json(conn, {"status": "fail"})
            except Exception:
                pass
            conn.close()

    # ------------------------------------------------------------ inisiator (sisi A)
    def connect(self, peer_name, peer_ip, peer_port):
        # --- Langkah 1
        n1 = str(_rng.randint(10**7, 10**8 - 1))
        m1 = {"step": 1, "id_a": self.name, "id_b": peer_name, "n1": n1}
        k = socket.create_connection(self.kdc, timeout=10)
        kf = k.makefile("r")
        print(f"[{self.name}] === Langkah 1 -> KDC: {m1}")
        send_json(k, m1)
        # --- Langkah 2
        resp = recv_json(kf)
        k.close()
        if "error" in resp:
            print(f"[{self.name}] KDC menolak: {resp['error']}")
            return
        print(f"[{self.name}] === Langkah 2 <- KDC: {resp['data']}")
        plain = decrypt_text(self.key, resp["data"])
        ks, idb, n1r, ticket = plain.split("|", 3)
        if n1r != n1 or idb != peer_name:
            print(f"[{self.name}] Verifikasi N1/ID_B gagal!")
            return
        print(f"[{self.name}] Dekripsi OK -> Ks={ks}")

        # --- Langkah 3
        s = socket.create_connection((peer_ip, peer_port), timeout=10)
        f = s.makefile("r")
        print(f"[{self.name}] === Langkah 3 -> {peer_name} ({peer_ip}): ticket={ticket}")
        send_json(s, {"step": 3, "ticket": ticket})
        # --- Langkah 4
        m4 = recv_json(f)
        n2 = int(decrypt_text(ks, m4["data"]))
        print(f"[{self.name}] === Langkah 4 <- {peer_name}: {m4['data']} (N2={n2})")
        # --- Langkah 5
        c5 = encrypt_text(ks, str(n2 - 1))
        print(f"[{self.name}] === Langkah 5 -> {peer_name}: E(Ks,N2-1)={c5}")
        send_json(s, {"step": 5, "data": c5})
        ok = recv_json(f)
        if ok.get("status") != "ok":
            print(f"[{self.name}] {peer_name} menolak sesi.")
            s.close()
            return
        s.settimeout(None)
        self.sessions[peer_name] = {"sock": s, "ks": ks}
        print(f"[{self.name}] Sesi aman dengan {peer_name} siap. Ketik: send {peer_name} <pesan>")
        threading.Thread(target=self.recv_loop, args=(peer_name, f, ks), daemon=True).start()

    # ------------------------------------------------------------ chat dua arah
    def recv_loop(self, peer, f, ks):
        try:
            while True:
                m = recv_json(f)
                if m.get("type") == "msg":
                    pt = decrypt_text(ks, m["data"])
                    print(f"\n[{self.name}] <- dari {peer}")
                    print(f"      Ciphertext (hex): {m['data']}")
                    print(f"      Plaintext (ASCII): {pt}")
        except Exception:
            print(f"\n[{self.name}] Sesi dengan {peer} ditutup.")
            self.sessions.pop(peer, None)

    def send_msg(self, peer, text):
        ses = self.sessions.get(peer)
        if not ses:
            print("  belum ada sesi dengan", peer, "-> gunakan: connect")
            return
        ct = encrypt_text(ses["ks"], text)
        send_json(ses["sock"], {"type": "msg", "data": ct})
        print(f"[{self.name}] -> ke {peer}")
        print(f"      Plaintext (ASCII): {text}")
        print(f"      Ciphertext (hex) : {ct}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="Alice atau Bob")
    ap.add_argument("--kdc", required=True, help="IP KDC")
    ap.add_argument("--kdc-port", type=int, default=5000)
    ap.add_argument("--port", type=int, default=6000, help="port listen peer ini")
    args = ap.parse_args()

    key = input(f"Masukkan key master {args.name} (ASCII 16 char, sama dgn di KDC): ").strip()
    p = Peer(args.name, key, (args.kdc, args.kdc_port), args.port)
    threading.Thread(target=p.listen, daemon=True).start()

    print("\nPerintah:")
    print("  connect <nama> <ip> [port]  : jalankan langkah 1-5 ke lawan")
    print("  send <nama> <pesan>         : kirim pesan terenkripsi AES")
    print("  setkey <key baru>           : ganti key master sendiri")
    print("  sessions | quit")
    while True:
        try:
            line = input(f"{args.name}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        parts = line.split(maxsplit=2)
        cmd = parts[0]
        try:
            if cmd == "connect" and len(parts) >= 3:
                rest = line.split()
                port = int(rest[3]) if len(rest) > 3 else 6000
                p.connect(rest[1], rest[2], port)
            elif cmd == "send" and len(parts) == 3:
                p.send_msg(parts[1], parts[2])
            elif cmd == "setkey" and len(parts) >= 2:
                p.key = line.split(maxsplit=1)[1]
                print("  key master diganti ->", p.key, "(ubah juga di KDC!)")
            elif cmd == "sessions":
                for n, s in p.sessions.items():
                    print(f"  {n}: Ks={s['ks']}")
            elif cmd == "quit":
                break
            else:
                print("  perintah tidak dikenal")
        except Exception as e:
            print("  error:", e)


if __name__ == "__main__":
    main()

# python3 peer.py --name <name> --kdc 192.168.100.82 -> kdc 