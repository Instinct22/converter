"""Public client update API. No admin session.

Catalog lives in data/updates/catalog.json. Installers live in data/updates/files/.
A missing catalog means there is no release yet.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.settings import DATA_DIR, settings

router = APIRouter()

_NAME = re.compile(r'^AegisGate-[A-Za-z0-9._-]+$')
_SHA = re.compile(r'^[0-9a-fA-F]{64}$')


def catalog_path() -> Path:
    return DATA_DIR / 'updates' / 'catalog.json'


def files_dir() -> Path:
    return DATA_DIR / 'updates' / 'files'


def _release(channel: str, platform: str, arch: str) -> dict | None:
    path = catalog_path()
    if not path.is_file():
        return None
    try:
        catalog = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(catalog, dict):
        return None
    entry = catalog.get(channel, {}).get(platform, {}).get(arch)
    if not isinstance(entry, dict):
        return None
    filename = str(entry.get('filename') or '')
    sha256 = str(entry.get('sha256') or '').lower()
    version = str(entry.get('version') or '')
    if not version or not _NAME.match(filename) or not _SHA.match(sha256):
        return None
    target = (files_dir() / filename).resolve()
    root = files_dir().resolve()
    if root not in target.parents or not target.is_file():
        return None
    base = settings.update_base_url.rstrip('/')
    return {
        'update': True,
        'version': version,
        'notes': str(entry.get('notes') or ''),
        'url': f'{base}/api/app/download/{filename}',
        'filename': filename,
        'sha256': sha256,
    }


@router.get('/api/app/latest')
def latest(platform: str = '', arch: str = '', channel: str = 'stable') -> dict:
    found = _release(channel.strip(), platform.strip(), arch.strip())
    if found is None:
        return {'update': False}
    return found


@router.get('/api/app/download/{filename}')
def download(filename: str) -> FileResponse:
    if not _NAME.match(filename):
        raise HTTPException(status_code=404, detail='not found')
    target = (files_dir() / filename).resolve()
    root = files_dir().resolve()
    if root not in target.parents or not target.is_file():
        raise HTTPException(status_code=404, detail='not found')
    return FileResponse(target, filename=filename, media_type='application/octet-stream')
