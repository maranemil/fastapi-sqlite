import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .models import TokenTable
from .config import JWT_SECRET_KEY, JWT_REFRESH_SECRET_KEY, ALGORITHM


def decodeJWT(jw_token: str):
    try:
        # Decode and verify the token
        payload = jwt.decode(jw_token, JWT_SECRET_KEY, ALGORITHM)
        return payload
    except InvalidTokenError:
        return None


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jw_token: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = decodeJWT(jw_token)
        except:
            payload = None

        if payload:
            isTokenValid = True
        return isTokenValid


jwt_bearer = JWTBearer()


# def token_required(func):
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#
#         payload = jwt.decode(kwargs['dependencies'], JWT_SECRET_KEY, ALGORITHM)
#         user_id = payload['sub']
#         data = kwargs['session'].query(models.TokenTable).filter_by(user_id=user_id, access_toke=kwargs['dependencies'],
#                                                                     status=True).first()
#         if data:
#             return func(kwargs['dependencies'], kwargs['session'])
#
#         else:
#             return {'msg': "Token blocked"}
#
#     return wrapper