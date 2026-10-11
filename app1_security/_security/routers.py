from fastapi import APIRouter,Query,Header
from _security.keycloak_services import KeycloakServices
from _security.models import *
from fastapi import Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter(prefix="/auth",tags=["Authentication"])
security = HTTPBearer()

@router.get("/well-known/openid-configuration​")
def _wellKnown_Opid_config():
    return KeycloakServices.wellKnown_Opid_config()

@router.get("/jwks")
def _jwks():
    return KeycloakServices.jwks()

@router.get("/authorize")
def _authorize():
        return KeycloakServices.authorize()

@router.get("/callback")
def _callback(
    code: str = Query(...),
    state: str = Query(...)
):
    return KeycloakServices.callback(
        code=code,
        state=state
    )

@router.post("/token")
def _token(request: TokenRequest):
    return KeycloakServices.get_token(
        request
    )
@router.get("/session")
def _session(credentials: HTTPAuthorizationCredentials = Security(security)):
    return KeycloakServices.get_session(credentials.credentials)

@router.post("/logout")
def _logout(request: LogoutRequest):
    return KeycloakServices.logout(
        request.refresh_token
    )