from typing import Annotated
import hmac

from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session

from app.database import get_session
from app.settings import settings

SessionDep = Annotated[Session, Depends(get_session)]


def credentials_ok(username: str, password: str) -> bool:
    try:
        user_ok = hmac.compare_digest(
            username.strip().encode('utf-8'),
            settings.admin_username.encode('utf-8'),
        )
        pass_ok = hmac.compare_digest(
            password.encode('utf-8'),
            settings.admin_password.encode('utf-8'),
        )
    except Exception:
        return False
    return settings.admin_password.strip() not in {'', 'changeme'} and user_ok and pass_ok


def request_authorized(request: Request) -> bool:
    return bool(request.session.get('admin'))


def require_admin(request: Request) -> None:
    if not request_authorized(request):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='auth required')
