from pydantic import BaseModel
from typing import Optional

class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str] = None
    state: Optional[str] = None
    refresh_token: Optional[str] = None

class RefreshTokenRequest(BaseModel):
        refresh_token: str

class LogoutRequest(BaseModel):
        refresh_token: str