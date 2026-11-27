import argparse, asyncio, json, ssl, hmac, hashlib, sys

APP_HMAC_SECRET = None  # Client не знає серверний секрет; для демо HMAC payload робимо на клієнті з тим же секретом
# Для навчальних цілей ми синхронізуємо секрет через CLI параметр (небезпечно в реальному житті).

def make_ssl_context(ca, cert=None, key=None):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key)
    return ctx

async def run(args):
    global APP_HMAC_SECRET
    APP_HMAC_SECRET = bytes.fromhex(args.shared_hmac) if args.shared_hmac else b"demo-secret-32bytes-demo-secret-32"[:32]
    ctx = make_ssl_context(args.ca, args.cert, args.key)
    reader, writer = await asyncio.open_connection(args.host, args.port, ssl=ctx, server_hostname=args.server_name)
    sslobj = writer.get_extra_info('ssl_object')
    print('TLS:', sslobj.version(), sslobj.cipher())

    async def send(obj):
        writer.write((json.dumps(obj)+'\n').encode()); await writer.drain()
    async def recv():
        return json.loads((await reader.readline()).decode())

    # AUTH
    await send({"op":"auth","username":args.user,"password":args.password})
    r = await recv()
    if not r.get('ok'):
        print('AUTH FAIL:', r); return
    token = r['token']
    print('AUTH OK, token=', token)

    # DATA
    payload = args.msg
    tag = hmac.new(APP_HMAC_SECRET, payload.encode(), 'sha256').hexdigest()
    await send({"op":"data","token":token,"payload":payload,"hmac":tag})
    r = await recv()
    print('RESP:', r)

    await send({"op":"quit"}); await recv()
    writer.close(); await writer.wait_closed()

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8443)
    ap.add_argument('--server-name', default='localhost')
    ap.add_argument('--ca', required=True)
    ap.add_argument('--cert')
    ap.add_argument('--key')
    ap.add_argument('--user', required=True)
    ap.add_argument('--password', required=True)
    ap.add_argument('--msg', default='hello')
    ap.add_argument('--shared_hmac', help='32-byte hex secret for demo app-level HMAC (educational only)')
    args = ap.parse_args()
    asyncio.run(run(args))
