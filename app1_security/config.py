from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

#region security_config

class Settings(BaseSettings):
    CLIENT_ID : str
    CLIENT_SECRET : Optional[str]
    REDIRECT_URI : Optional[str]
    AUTH_REALM:str
    AUTH_BACKEND_URL: str
    AUTH_TIMEOUT:int
    CORS_ALLOWED_ORIGINS:list[str]
    SESSION_EXPIRE_AGE:int
    CSRF_COOKIE_NAME:str
    CSRF_HEADER_NAME:str
    SECURE_SSL_REDIRECT:bool
    AUTH_COOKIE_SAMESITE:str
    SECURE_COOKIES:bool 
    ADMIN_USERNAME:str
    ADMIN_PASSWORD:str
    model_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding="utf-8",
    extra="ignore"
)

settings = Settings()

#endregion
