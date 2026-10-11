#builtin imports
from fastapi.security import HTTPBearer
from keycloak import KeycloakOpenID,KeycloakAdmin
from fastapi import status,HTTPException
from keycloak.pkce_utils import (generate_code_challenge,generate_code_verifier)
import secrets
from jose import JWTError, jwt

#our own imports
import config 
from _security.session_repository import PKCERepository
from _security.models import *

#Keycloak OpenID Engine for Authentication Operations
keycloak_openid = KeycloakOpenID(
    server_url=config.settings.AUTH_BACKEND_URL,
    realm_name=config.settings.AUTH_REALM,
    client_id=config.settings.CLIENT_ID,
    #client_secret_key=config.settings.CLIENT_SECRET
)

#Keycloak Admin Engine for Session,user & Token Management 
keycloak_admin = KeycloakAdmin(
    server_url=config.settings.AUTH_BACKEND_URL,
    username=config.settings.ADMIN_USERNAME,
    password=config.settings.ADMIN_PASSWORD,
    realm_name=config.settings.AUTH_REALM,
    user_realm_name="master",
    client_id="admin-cli"
)

security = HTTPBearer()

#region keyclockServices
class KeycloakServices:
        
        _cached_jwks = None

        '''Return the Full Keycloak Configurations'''
        @staticmethod
        def wellKnown_Opid_config():
                try:
                        opid_configs = keycloak_openid.well_known()
                        return {
                               "success": True, 
                               "message": "opid_configs retrieved successfully",
                               "data": opid_configs
                        }
                except Exception as e:
                        raise HTTPException(
                                 status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                                details = f"Failed to get opid_configs: {str(e)}"
                        )
                      
        
        '''jwks returns json web key sets contains Keycloak public keys list'''
        @staticmethod
        def jwks():
                try:
                        jwks = keycloak_openid.certs()
                        return {
                               "success": True, 
                               "message": "JWKS retrieved successfully",
                               "data": jwks
                        }
                except Exception as e:
                        raise HTTPException (
                                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail=f"Failed to get public keys: {str(e)}"
                        )
                               
        '''
        authorize generates state,codechalleng,codeverifier for pkce flow
        And returns Auth_url
        '''
        @staticmethod
        def authorize():

                try:
                        #generate state,codeChallenge,codeVerifier for pkce flow
                        state = secrets.token_urlsafe(32)
                        code_verifier= generate_code_verifier()
            
                        code_challenge,code_challenge_method = (
                                generate_code_challenge(code_verifier)
                        )
                    
                        #save this code_verifier for getting acess_token
                        PKCERepository.save(state=state,verifier=code_verifier)


                        #generate Keycloak auth_url
                        auth_url = keycloak_openid.auth_url(
                                redirect_uri=config.settings.REDIRECT_URI,
                                scope="openid profile email",
                                state=state,
                                code_challenge=code_challenge,
                                code_challenge_method=code_challenge_method
                        )

                        #On sucess returning autorization_url to client
                        return {
                                "autorization_url":auth_url,
                                "state":state, 
                        }
                except Exception as e:
                        return {
                                "status" : status.HTTP_409_CONFLICT,
                                "message" : "Failed to generate authorization URL",
                                "Details" : str(e)
                        }

        '''
        Callback is used to exchange the Auth code with help 
        of code verifier and returns acess_token
        '''
        @staticmethod
        def callback(code: str, state: str):

                try:

                        return {
                                "success": True,
                                "message": "Authorization code received successfully",
                                "data": {
                                "code": code,
                                "state": state
                                }
                                }

                except Exception as ex:

                        raise HTTPException(
                        status_code=500,
                        detail=f"Token exchange failed: {str(ex)}"
                        )
        
        '''logout is used to kill the session by live refresh token'''
        @staticmethod
        def logout(refresh_token: str):

                        try:
                                keycloak_openid.logout(refresh_token)

                                return {
                                "success": True,
                                "message": "Logout successful"
                                }

                        except Exception as e:
                                raise HTTPException(
                                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                detail=f"Logout failed: {str(e)}"
                                )
       
        '''get_token is used to generate the acess_token,refresh_token,Id_token'''
        @staticmethod
        def get_token(request: TokenRequest):

                try:

                        if request.grant_type == "authorization_code":

                                if not request.code or not request.state:
                                        raise HTTPException(
                                        status_code=400,
                                        detail="code and state are required"
                                        )

                                pkce_data = PKCERepository.get(request.state)

                                if not pkce_data:
                                        raise HTTPException(
                                        status_code=400,
                                        detail="Invalid or expired state"
                                        )

                                code_verifier = pkce_data["code_verifier"]
                                
                                token_response = keycloak_openid.token(
                                        grant_type="authorization_code",
                                        code=request.code,
                                        redirect_uri=config.settings.REDIRECT_URI,
                                        code_verifier=code_verifier
                                )

                                PKCERepository.remove(request.state)

                        elif request.grant_type == "refresh_token":

                                if not request.refresh_token:
                                        raise HTTPException(
                                        status_code=400,
                                        detail="refresh_token is required"
                                        )

                                token_response = keycloak_openid.refresh_token(
                                        request.refresh_token
                                )

                        else:
                                raise HTTPException(
                                        status_code=400,
                                        detail=f"Unsupported grant_type: {request.grant_type}"
                                )

                        return {
                        "success": True,
                        "message": "Token issued successfully",
                        "data": token_response
                        }

                except HTTPException:
                        raise

                except Exception as ex:
                        raise HTTPException(
                        status_code=500,
                        detail=f"Token operation failed: {str(ex)}"
                        )


        '''get_public_key fetches the public key from Keycloak JWKS for token validation'''
        @classmethod
        def get_public_key(cls, kid: str):
            """Fetch and cache public keys from Keycloak JWKS."""
            if not cls._cached_jwks:
                cls._cached_jwks = cls.jwks().get("data", {})

            keys = cls._cached_jwks.get("keys", [])
            for key in keys:
                if key.get("kid") == kid:
                    return key

            cls._cached_jwks = cls.jwks().get("data", {})   
            for key in cls._cached_jwks.get("keys", []):
                if key.get("kid") == kid:
                    return key
            return None

        '''decode_and_validate_token decodes and validates the token signature, audience, and expiry'''
        @classmethod
        def decode_and_validate_token(cls, token: str) -> dict:
            """Locally decodes and verifies the token signature, audience, and expiry."""
            try:
                if token.startswith("Bearer "):
                    token = token.split(" ", 1)[1]

                # 1. Decode the token header to get the 'kid'
                unverified_header = jwt.get_unverified_header(token)
                kid = unverified_header.get("kid")
                if not kid:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, 
                        detail="Invalid token header: missing kid"
                    )

                # 2. Get the matching public key
                key = cls.get_public_key(kid)
                if not key:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, 
                        detail="Invalid token: unknown public key"
                    )

                # 3. Format issuer cleanly (strip any trailing slashes)
                base_url = config.settings.AUTH_BACKEND_URL.rstrip("/")
                issuer = f"{base_url}/realms/{config.settings.AUTH_REALM}"

                payload = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    issuer=issuer,
                    options={
                        "verify_aud": False,    
                        "verify_iss": True,
                        "verify_exp": True
                    }
                )
                return payload

            except JWTError as err:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Token validation failed: {str(err)}",
                    headers={"WWW-Authenticate": "Bearer"}
                )

        '''get_session validates the access_token and returns user session details'''
        @classmethod
        def get_session(cls, access_token: str):
            token_claims = cls.decode_and_validate_token(access_token)
            return {
                "authenticated": True,
                "user": {
                    "sub": token_claims.get("sub"),
                    "username": token_claims.get("preferred_username"),
                    "email": token_claims.get("email"),
                    "roles": token_claims.get("realm_access", {}).get("roles", [])
                }
            }
#end region 
