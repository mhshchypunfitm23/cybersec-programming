import argparse
import os
import time
import base64
import secrets
from logger import get_logger
from sym import SymKeyStore, encrypt_gcm, decrypt_gcm, encrypt_cbc_hmac, decrypt_cbc_hmac
from asym import gen_rsa, save_priv_pem, save_pub_pem, load_priv, load_pub, rsa_encrypt, rsa_decrypt, sign, verify
from hybrid import encrypt_hybrid, decrypt_hybrid

logger = get_logger()

def _resolve_sym_key(args, ks: SymKeyStore) -> bytes:
    if getattr(args, "key", None):
        try:
            raw = base64.b64decode(args.key)
            if len(raw) not in (16, 24, 32):
                raise ValueError("Довжина ключа має бути 128, 192 або 256 біт")
            return raw
        except Exception as e:
            raise ValueError(f"Некоректний Base64-формат ключа: {e}")
    return ks.get(args.label)

def sym_cmd(args):
    ks = SymKeyStore()
    if args.action == "new":
        meta, key = ks.new(args.label, bits=args.bits)
        logger.info("sym.key.generate_or_rotate", extra={"extra": meta})
        print(f"[OK] Ключ '{args.label}' (v{meta['version']}, {args.bits}-bit) збережено у сховищі.")
        print("Base64 KEY:", base64.b64encode(key).decode())
    elif args.action == "enc":
        key = _resolve_sym_key(args, ks)
        t0 = time.perf_counter()
        if args.mode == "gcm":
            encrypt_gcm(args.infile, args.outfile, key)
        else:
            encrypt_cbc_hmac(args.infile, args.outfile, key)
        dt = time.perf_counter() - t0
        logger.info("sym.encrypt", extra={"extra": {"mode": args.mode, "bits": len(key)*8, "in": args.infile, "sec": round(dt, 5)}})
        print(f"[OK] Зашифровано ({args.mode.upper()}, {len(key)*8}-bit) за {dt:.4f} с -> {args.outfile}")
    elif args.action == "dec":
        key = _resolve_sym_key(args, ks)
        t0 = time.perf_counter()
        if args.mode == "gcm":
            decrypt_gcm(args.infile, args.outfile, key)
        else:
            decrypt_cbc_hmac(args.infile, args.outfile, key)
        dt = time.perf_counter() - t0
        logger.info("sym.decrypt", extra={"extra": {"mode": args.mode, "in": args.infile, "sec": round(dt, 5)}})
        print(f"[OK] Розшифровано ({args.mode.upper()}) за {dt:.4f} с -> {args.outfile}")

def rsa_cmd(args):
    if args.action == "gen":
        t0 = time.perf_counter()
        priv, pub = gen_rsa(args.bits)
        os.makedirs(os.path.dirname(args.priv) or ".", exist_ok=True)
        save_priv_pem(priv, args.priv, args.password)
        save_pub_pem(pub, args.pub)
        dt = time.perf_counter() - t0
        logger.info("rsa.keygen", extra={"extra": {"bits": args.bits, "sec": round(dt, 4)}})
        print(f"[OK] RSA-{args.bits} ключі згенеровано за {dt:.3f} с ({args.priv}, {args.pub})")
    elif args.action == "enc":
        pub = load_pub(args.pub)
        ct = rsa_encrypt(pub, open(args.infile, "rb").read())
        os.makedirs(os.path.dirname(args.outfile) or ".", exist_ok=True)
        open(args.outfile, "wb").write(ct)
        logger.info("rsa.encrypt", extra={"extra": {"in": args.infile}})
        print(f"[OK] RSA-OAEP шифрування виконано -> {args.outfile}")
    elif args.action == "dec":
        priv = load_priv(args.priv, args.password)
        pt = rsa_decrypt(priv, open(args.infile, "rb").read())
        os.makedirs(os.path.dirname(args.outfile) or ".", exist_ok=True)
        open(args.outfile, "wb").write(pt)
        logger.info("rsa.decrypt", extra={"extra": {"in": args.infile}})
        print(f"[OK] RSA-OAEP розшифрування виконано -> {args.outfile}")
    elif args.action == "sign":
        priv = load_priv(args.priv, args.password)
        sig = sign(priv, open(args.infile, "rb").read())
        os.makedirs(os.path.dirname(args.sig) or ".", exist_ok=True)
        open(args.sig, "wb").write(sig)
        logger.info("rsa.sign", extra={"extra": {"in": args.infile, "sig": args.sig}})
        print(f"[OK] Цифровий підпис RSA-PSS створено -> {args.sig}")
    elif args.action == "verify":
        pub = load_pub(args.pub)
        ok = verify(pub, open(args.sig, "rb").read(), open(args.infile, "rb").read())
        logger.info("rsa.verify", extra={"extra": {"in": args.infile, "valid": ok}})
        print("[OK] Перевірка підпису: ПІДПИС ДІЙСНИЙ" if ok else "[ERROR] Перевірка підпису: НЕВІРНИЙ ПІДПИС!")

def hybrid_cmd(args):
    if args.action == "enc":
        t0 = time.perf_counter()
        encrypt_hybrid(args.pub, args.infile, args.outfile)
        dt = time.perf_counter() - t0
        logger.info("hybrid.encrypt", extra={"extra": {"in": args.infile, "sec": round(dt, 5)}})
        print(f"[OK] Гібридне шифрування (RSA-OAEP + AES-256-GCM) виконано за {dt:.4f} с -> {args.outfile}")
    else:
        t0 = time.perf_counter()
        decrypt_hybrid(args.priv, args.password, args.infile, args.outfile)
        dt = time.perf_counter() - t0
        logger.info("hybrid.decrypt", extra={"extra": {"in": args.infile, "sec": round(dt, 5)}})
        print(f"[OK] Гібридне розшифрування виконано за {dt:.4f} с -> {args.outfile}")

def bench_cmd(args):
    os.makedirs("outputs", exist_ok=True)
    key = secrets.token_bytes(32)
    print("\n=== БЕНЧМАРК СИМЕТРИЧНОГО ШИФРУВАННЯ (AES-256) ===")
    print(f"{'Розмір':<10} | {'Режим':<10} | {'Шифрування (с)':<16} | {'Дешифрування (с)':<16}")
    print("-" * 60)
    for s in args.sizes:
        size = int(float(s[:-2]) * 1024 * 1024) if s.lower().endswith("mb") else int(float(s[:-2]) * 1024)
        path = f"outputs/bench_{s}.bin"
        with open(path, "wb") as f:
            f.write(secrets.token_bytes(size))
        for mode in args.modes:
            t0 = time.perf_counter()
            if mode == "gcm":
                encrypt_gcm(path, path + ".enc", key)
            else:
                encrypt_cbc_hmac(path, path + ".enc", key)
            te = time.perf_counter() - t0

            t1 = time.perf_counter()
            if mode == "gcm":
                decrypt_gcm(path + ".enc", path + ".dec", key)
            else:
                decrypt_cbc_hmac(path + ".enc", path + ".dec", key)
            td = time.perf_counter() - t1
            print(f"{s:<10} | {mode.upper():<10} | {te:<16.5f} | {td:<16.5f}")

    print("\n=== БЕНЧМАРК АСИМЕТРИЧНОГО ШИФРУВАННЯ (RSA) ===")
    print(f"{'Розмір ключа':<14} | {'Генерація (с)':<15} | {'Шифр. 64B (мс)':<16} | {'Дешифр. 64B (мс)':<16}")
    print("-" * 68)
    sample_block = secrets.token_bytes(64)
    for bits in args.rsa_bits:
        t0 = time.perf_counter()
        priv, pub = gen_rsa(bits)
        tg = time.perf_counter() - t0

        t1 = time.perf_counter()
        ct = rsa_encrypt(pub, sample_block)
        te = (time.perf_counter() - t1) * 1000

        t2 = time.perf_counter()
        _ = rsa_decrypt(priv, ct)
        td = (time.perf_counter() - t2) * 1000
        print(f"RSA-{bits:<10} | {tg:<15.4f} | {te:<16.3f} | {td:<16.3f}")
    logger.info("bench.completed", extra={"extra": {"sizes": args.sizes, "rsa_bits": args.rsa_bits}})

def main():
    p = argparse.ArgumentParser(description="Комплексний криптографічний застосунок (AES + RSA + Hybrid)")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("sym")
    ps.add_argument("action", choices=["new", "enc", "dec"])
    ps.add_argument("--label", default="default")
    ps.add_argument("--bits", type=int, default=256)
    ps.add_argument("--key", default=None)
    ps.add_argument("--mode", choices=["gcm", "cbc"], default="gcm")
    ps.add_argument("--in", dest="infile")
    ps.add_argument("--out", dest="outfile")
    ps.set_defaults(func=sym_cmd)

    pr = sub.add_parser("rsa")
    pr.add_argument("action", choices=["gen", "enc", "dec", "sign", "verify"])
    pr.add_argument("--bits", type=int, default=3072)
    pr.add_argument("--priv", default="keys/priv.pem")
    pr.add_argument("--pub", default="keys/pub.pem")
    pr.add_argument("--password", default="changeit")
    pr.add_argument("--in", dest="infile")
    pr.add_argument("--out", dest="outfile")
    pr.add_argument("--sig", default="outputs/sample.sig")
    pr.set_defaults(func=rsa_cmd)

    ph = sub.add_parser("hybrid")
    ph.add_argument("action", choices=["enc", "dec"])
    ph.add_argument("--pub", default="keys/pub.pem")
    ph.add_argument("--priv", default="keys/priv.pem")
    ph.add_argument("--password", default="changeit")
    ph.add_argument("--in", dest="infile")
    ph.add_argument("--out", dest="outfile")
    ph.set_defaults(func=hybrid_cmd)

    pb = sub.add_parser("bench")
    pb.add_argument("--sizes", nargs="+", default=["100KB", "1MB", "5MB"])
    pb.add_argument("--modes", nargs="+", default=["gcm", "cbc"])
    pb.add_argument("--rsa-bits", type=int, nargs="+", default=[2048, 3072, 4096])
    pb.set_defaults(func=bench_cmd)

    args = p.parse_args()
    try:
        args.func(args)
    except Exception as e:
        logger.error("crypto.error", extra={"extra": {"cmd": args.cmd, "error": str(e)}})
        print(f"[SECURITY EXCEPTION] {e}")

if __name__ == "__main__":
    main()
