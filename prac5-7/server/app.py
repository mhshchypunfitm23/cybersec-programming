from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import time, os
from server.models import EchoIn, LoginIn, TokenOut
from server.security import verify_password, create_token, decode_token, ensure_user, enable_totp, verify_totp
from server.ratelimit import RateLimiter
from server.logger_setup import get_logger

app = FastAPI(title='Secure Net App')
logger = get_logger()
rl = RateLimiter()

app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

# ----- Публічні ендпоінти -----
@app.get('/health')
def health():
    return {'ok': True, 'ts': int(time.time())}

@app.post('/echo-http')
def echo_http(e: EchoIn):
    # Нешифрований кінець (для кроку 2). Якщо запущено на 8080 — без TLS.
    return {'echo': e.msg}

# ----- Auth / JWT -----
@app.post('/auth/login', response_model=TokenOut)
def login(req: Request, data: LoginIn):
    ip = req.client.host if req.client else '0.0.0.0'
    if not rl.allow_login(ip, data.username):
        logger.info('rate.limit', extra={'extra':{'ip':ip,'user':data.username,'op':'login'}})
        raise HTTPException(status_code=429, detail='Too many attempts')
    try:
        user = ensure_user(data.username)
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    if not verify_password(data.password, user['pwd']):
        logger.info('auth.fail', extra={'extra':{'ip':ip,'user':data.username}})
        raise HTTPException(status_code=401, detail='Invalid credentials')
    if not verify_totp(data.username, data.otp):
        logger.info('auth.fail.otp', extra={'extra':{'ip':ip,'user':data.username}})
        raise HTTPException(status_code=401, detail='OTP required or invalid')
    tok = create_token(data.username, user.get('role','user'))
    logger.info('auth.ok', extra={'extra':{'ip':ip,'user':data.username}})
    return TokenOut(access_token=tok)

@app.post('/auth/enable-mfa')
def mfa_enable(data: LoginIn):
    # Демо: вмикаємо MFA, якщо користувач ввів вірний пароль (без сесії)
    user = ensure_user(data.username)
    if not verify_password(data.password, user['pwd']):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    secret = enable_totp(data.username)
    # otpauth URI для додавання в аутентифікатор
    import pyotp
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=data.username, issuer_name='SecureNetApp')
    logger.info('mfa.enable', extra={'extra':{'user':data.username}})
    return {'secret': secret, 'otpauth_uri': uri}

# ----- Захищені ендпоінти -----

def require_token(req: Request):
    auth = req.headers.get('Authorization','')
    if not auth.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Missing token')
    tok = auth.split(' ',1)[1]
    try:
        payload = decode_token(tok)
        return payload
    except Exception as e:
        raise HTTPException(status_code=401, detail='Invalid/expired token')

@app.post('/echo-https')
def echo_https(req: Request, e: EchoIn, payload=Depends(require_token)):
    if not rl.allow_echo():
        logger.info('rate.limit', extra={'extra':{'op':'echo'}})
        raise HTTPException(status_code=429, detail='Rate limited')
    logger.info('echo', extra={'extra':{'user':payload['sub'], 'len':len(e.msg)}})
    return {'user': payload['sub'], 'echo': e.msg}

@app.get('/whoami')
def whoami(payload=Depends(require_token)):
    return {'sub': payload['sub'], 'role': payload['role'], 'exp': payload['exp']}
