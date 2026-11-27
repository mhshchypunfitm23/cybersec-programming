from pydantic import BaseModel
class EchoIn(BaseModel):
    msg: str
class LoginIn(BaseModel):
    username: str
    password: str
    otp: str | None = None
class TokenOut(BaseModel):
    access_token: str
    token_type: str = 'bearer'
