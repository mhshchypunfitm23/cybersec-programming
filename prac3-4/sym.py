import os
import json
import base64
import struct
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag, InvalidSignature

MAGIC = b"CSYM"
VERSION = 1

class SymKeyStore:
    def __init__(self, path="keys/sym_store.json"):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def _load(self):
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def new(self, label: str, bits: int = 256):
        if bits not in (128, 192, 256):
            raise ValueError("Підтримуються лише ключі 128, 192 або 256 біт")
        master_secret = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=bits // 8, salt=salt, iterations=100_000)
        derived_key = kdf.derive(master_secret)

        store = self._load()
        version = store.get(label, {}).get("version", 0) + 1
        meta = {
            "label": label,
            "version": version,
            "bits": bits,
            "salt_b64": base64.b64encode(salt).decode(),
            "key_b64": base64.b64encode(derived_key).decode(),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        store[label] = meta
        self._save(store)
        return {"label": label, "version": version, "bits": bits}, derived_key

    def get(self, label: str) -> bytes:
        store = self._load()
        if label not in store:
            raise KeyError(f"Ключ із міткою '{label}' не знайдено у сховищі")
        return base64.b64decode(store[label]["key_b64"])

def _pack_header(hdr: dict) -> bytes:
    raw = json.dumps(hdr).encode("utf-8")
    return MAGIC + struct.pack(">BH", VERSION, len(raw)) + raw

def _unpack_header(fp) -> dict:
    magic = fp.read(4)
    if magic != MAGIC:
        raise ValueError("Невірний формат зашифрованого файлу (пошкоджений заголовок)")
    ver, hlen = struct.unpack(">BH", fp.read(3))
    return json.loads(fp.read(hlen).decode("utf-8"))

def encrypt_gcm(in_path: str, out_path: str, key: bytes):
    if len(key) not in (16, 24, 32):
        raise ValueError("Невірний розмір ключа AES (потрібно 16, 24 або 32 байти)")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    nonce = secrets.token_bytes(12)
    hdr = {"mode": "gcm", "bits": len(key) * 8}
    aad = _pack_header(hdr)
    data = open(in_path, "rb").read()
    ct = AESGCM(key).encrypt(nonce, data, aad)
    with open(out_path, "wb") as f:
        f.write(aad + nonce + ct)

def decrypt_gcm(in_path: str, out_path: str, key: bytes):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(in_path, "rb") as f:
        hdr = _unpack_header(f)
        f.seek(0)
        aad = f.read(7 + len(json.dumps(hdr).encode("utf-8")))
        nonce = f.read(12)
        ct = f.read()
    try:
        pt = AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise ValueError("Помилка автентифікації GCM: невірний ключ або дані було змінено!")
    open(out_path, "wb").write(pt)

def encrypt_cbc_hmac(in_path: str, out_path: str, key: bytes):
    if len(key) not in (16, 24, 32):
        raise ValueError("Невірний розмір ключа AES")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    iv = secrets.token_bytes(16)
    mac_key = hashes.Hash(hashes.SHA256())
    mac_key.update(key + b"hmac-auth")
    mkey = mac_key.finalize()

    hdr = {"mode": "cbc-hmac", "bits": len(key) * 8}
    aad = _pack_header(hdr)
    data = open(in_path, "rb").read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()

    h = hmac.HMAC(mkey, hashes.SHA256())
    h.update(aad + iv + ct)
    tag = h.finalize()

    with open(out_path, "wb") as f:
        f.write(aad + iv + tag + ct)

def decrypt_cbc_hmac(in_path: str, out_path: str, key: bytes):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    mac_key = hashes.Hash(hashes.SHA256())
    mac_key.update(key + b"hmac-auth")
    mkey = mac_key.finalize()

    with open(in_path, "rb") as f:
        hdr = _unpack_header(f)
        f.seek(0)
        aad = f.read(7 + len(json.dumps(hdr).encode("utf-8")))
        iv = f.read(16)
        tag = f.read(32)
        ct = f.read()

    h = hmac.HMAC(mkey, hashes.SHA256())
    h.update(aad + iv + ct)
    try:
        h.verify(tag)
    except InvalidSignature:
        raise ValueError("Помилка перевірки цілісності HMAC-SHA256: файл пошкоджено або ключ невірний!")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    open(out_path, "wb").write(pt)
