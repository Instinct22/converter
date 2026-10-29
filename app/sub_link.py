from __future__ import annotations

from app.models import AppSetting, Client
from app.settings import settings
from app.util import new_token
from sqlmodel import Session

_cached = ''


def init_sub_path(session: Session) -> str:
    global _cached
    env = (settings.sub_path or '').strip().strip('/')
    if env:
        _cached = env
        return _cached
    row = session.get(AppSetting, 'sub_path')
    if row and row.value.strip():
        _cached = row.value.strip().strip('/')
        return _cached
    value = new_token(16)
    if row is None:
        session.add(AppSetting(key='sub_path', value=value))
    else:
        row.value = value
        session.add(row)
    session.commit()
    _cached = value
    return _cached


def sub_path() -> str:
    return _cached or (settings.sub_path or '').strip().strip('/') or 'sub'


def client_sub_url(client: Client) -> str:
    base = settings.public_base_url.rstrip('/')
    return f'{base}/{sub_path()}/{client.sub_token}'
