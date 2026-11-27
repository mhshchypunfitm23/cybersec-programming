import argparse, asyncio, json, os, ssl, time, hmac, hashlib, secrets, ipaddress
from typing import Dict

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "server.jsonl")
USERS = json.load(open("users.json","r",encoding="utf-8"))

def log(event: str, **kw):
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    rec.update(kw)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def make_ssl_context(cert, key, ca, require_client_cert=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    if ca:
        ctx.load_verify_locations(cafile=ca)
    if require_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

def hash_secret(s: str) -> str:
    # demo HMAC secret (server-side) for integrity of app payloads
    return hashlib.sha256(("pepper-" + s).encode()).hexdigest()

TOKENS: Dict[str,str] = {}  # token -> username
APP_HMAC_SECRET = bytes.fromhex(os.environ.get("SHARED_HMAC", "")) if os.environ.get("SHARED_HMAC") else b"demo-secret-32bytes-demo-secret-32"[:32]

async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    sslobj = writer.get_extra_info("ssl_object")
    cipher = sslobj.cipher() if sslobj else None
    version = sslobj.version() if sslobj else None
    log("tls.handshake", peer=str(peer), tls_version=version, cipher=cipher)

    async def send(obj):
        data = (json.dumps(obj) + "\n").encode()
        writer.write(data); await writer.drain()

    try:
        # 1) AUTH
        line = await reader.readline()
        msg = json.loads(line.decode())
        if msg.get("op") != "auth":
            await send({"ok": False, "err": "first message must be auth"})
            log("auth.fail", peer=str(peer), reason="no_auth_message")
            writer.close(); await writer.wait_closed(); return

        user = msg.get("username","")
        pwd  = msg.get("password","")
        import bcrypt
        h = USERS.get(user)
        if not h or not bcrypt.checkpw(pwd.encode(), h.encode()):
            await send({"ok": False, "err": "invalid_credentials"})
            log("auth.fail", peer=str(peer), user=user, reason="invalid")
            writer.close(); await writer.wait_closed(); return

        token = secrets.token_hex(16)
        TOKENS[token] = user
        await send({"ok": True, "token": token, "tls": {"version": version, "cipher": cipher}})
        log("auth.ok", peer=str(peer), user=user)

        # 2) DATA (with HMAC)
        while not reader.at_eof():
            line = await reader.readline()
            if not line: break
            try:
                msg = json.loads(line.decode())
            except Exception:
                await send({"ok": False, "err": "bad_json"})
                continue
            if msg.get("op") == "quit":
                await send({"ok": True, "bye": True}); break

            if msg.get("op") != "data":
                await send({"ok": False, "err": "unsupported_op"}); continue

            if msg.get("token") not in TOKENS:
                await send({"ok": False, "err": "invalid_token"})
                log("data.invalid_token", peer=str(peer)); continue

            payload = msg.get("payload","")
            tag = bytes.fromhex(msg.get("hmac","")) if msg.get("hmac") else b""
            hm = hmac.new(APP_HMAC_SECRET, payload.encode(), digestmod="sha256").digest()
            if not hmac.compare_digest(hm, tag):
                await send({"ok": False, "err": "bad_hmac"})
                log("data.bad_hmac", peer=str(peer)); continue

            # Echo back, attach server ack with own HMAC
            resp = {"ok": True, "echo": payload}
            resp_hmac = hmac.new(APP_HMAC_SECRET, json.dumps(resp).encode(), "sha256").hexdigest()
            resp["hmac"] = resp_hmac
            await send(resp)
            log("data.ok", peer=str(peer), user=TOKENS[msg["token"]], bytes=len(payload.encode()))
    except Exception as e:
        log("conn.error", peer=str(peer), err=str(e))
    finally:
        writer.close(); await writer.wait_closed()
        log("conn.closed", peer=str(peer))

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ca", required=False)
    ap.add_argument("--require-client-cert", action="store_true")
    args = ap.parse_args()

    ctx = make_ssl_context(args.cert, args.key, args.ca, args.require_client_cert)
    srv = await asyncio.start_server(handle, args.host, args.port, ssl=ctx)
    addr = ", ".join(str(s.getsockname()) for s in srv.sockets)
    print(f"TLS server on {addr}")
    async with srv:
        await srv.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
