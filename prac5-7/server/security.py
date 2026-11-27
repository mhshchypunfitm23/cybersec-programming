import time, os, bcrypt, jwt, pyotp, json
from typing import Optional

JWT_SECRET = os.environ.get('JWT_SECRET', 'dev-secret-change-me')
JWT_ALG = 'HS256'
JWT_TTL = int(os.environ.get('JWT_TTL', '900'))  # 15 хв

USERS_PATH = 'server/users.json'
USERS = json.load(open(USERS_PATH,'r',encoding='utf-8')) if os.path.exists(USERS_PATH) else {}

# USERS формат: {"alice": {"pwd":"<bcrypt>", "role":"user", "totp_secret": null}}

def verify_password(plain, hashed):
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_token(sub: str, role: str):
    now = int(time.time())
    payload = {"sub": sub, "role": role, "iat": now, "exp": now + JWT_TTL}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(tok: str):
    return jwt.decode(tok, JWT_SECRET, algorithms=[JWT_ALG])

def ensure_user(username: str):
    user = USERS.get(username)
    if not user: raise ValueError('user_not_found')
    return user

def enable_totp(username: str):
    user = ensure_user(username)
    if user.get('totp_secret'): return user['totp_secret']
    secret = pyotp.random_base32()
    user['totp_secret'] = secret
    json.dump(USERS, open(USERS_PATH,'w',encoding='utf-8'), ensure_ascii=False, indent=2)
    return secret

def verify_totp(username: str, otp: Optional[str]):
    user = ensure_user(username)
    secret = user.get('totp_secret')
    if not secret:
        return True  # MFA не ввімкнено
    if not otp:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(otp, valid_window=1)
