from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlmodel import Session

from app.database import get_session

SessionDep = Annotated[Session, Depends(get_session)]


def require_admin(request: Request) -> None:
    if not request.session.get('admin'):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='auth required')
