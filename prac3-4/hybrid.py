import os
import json
import struct
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from asym import rsa_encrypt, rsa_decrypt, load_priv, load_pub

MAGIC = b"CHYB"
VERSION = 1

def encrypt_hybrid(pub_pem_path: str, in_path: str, out_path: str):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    pub = load_pub(pub_pem_path)
    session_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    enc_session_key = rsa_encrypt(pub, session_key)
    hdr = json.dumps({"v": VERSION, "alg": "RSA-OAEP+AES-256-GCM"}).encode("utf-8")
    prefix = MAGIC + struct.pack(">HH", len(hdr), len(enc_session_key)) + hdr + enc_session_key + nonce

    plaintext = open(in_path, "rb").read()
    ciphertext = AESGCM(session_key).encrypt(nonce, plaintext, prefix)

    with open(out_path, "wb") as f:
        f.write(prefix + ciphertext)

def decrypt_hybrid(priv_pem_path: str, password: str, in_path: str, out_path: str):
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    priv = load_priv(priv_pem_path, password)

    with open(in_path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Невірний формат гібридного контейнера")
        hlen, klen = struct.unpack(">HH", f.read(4))
        hdr = f.read(hlen)
        enc_session_key = f.read(klen)
        nonce = f.read(12)
        ciphertext = f.read()

    prefix = magic + struct.pack(">HH", hlen, klen) + hdr + enc_session_key + nonce
    session_key = rsa_decrypt(priv, enc_session_key)
    plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, prefix)

    open(out_path, "wb").write(plaintext)
