from typing import Annotated
import base64
import hmac

from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session

from app.database import get_session
from app.settings import settings

SessionDep = Annotated[Session, Depends(get_session)]

WWW_AUTHENTICATE = {'WWW-Authenticate': 'Basic realm="Master"'}


def credentials_ok(username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(
        username.strip().encode('utf-8'),
        settings.admin_username.encode('utf-8'),
    )
    pass_ok = hmac.compare_digest(
        password.encode('utf-8'),
        settings.admin_password.encode('utf-8'),
    )
    return user_ok and pass_ok


def request_authorized(request: Request) -> bool:
    header = request.headers.get('authorization') or ''
    if not header.lower().startswith('basic '):
        return False
    try:
        raw = base64.b64decode(header.split(' ', 1)[1].strip()).decode('utf-8')
    except Exception:
        return False
    username, sep, password = raw.partition(':')
    if not sep:
        return False
    return credentials_ok(username, password)


def require_admin(request: Request) -> None:
    if not request_authorized(request):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='auth required',
            headers=WWW_AUTHENTICATE,
        )
