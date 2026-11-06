"""Public client update API. No admin session.

Catalog lives in data/updates/catalog.json. Installers live in data/updates/files/.
A missing catalog means there is no release yet.
The catalog points at one current file. Older installers can stay on disk
and stay downloadable by exact name until an admin deletes them.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from app.settings import DATA_DIR, settings
from app.util import format_bytes

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
    target = _installer_path(filename)
    if target is None or not target.is_file():
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


def _installer_path(filename: str) -> Path | None:
    if not _NAME.match(filename):
        return None
    root = files_dir().resolve()
    target = (files_dir() / filename).resolve()
    if root not in target.parents:
        return None
    return target


def _load_catalog() -> dict:
    path = catalog_path()
    if not path.is_file():
        return {}
    try:
        catalog = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    return catalog if isinstance(catalog, dict) else {}


def _save_catalog(catalog: dict) -> None:
    path = catalog_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def published_entries() -> list[dict]:
    rows: list[dict] = []
    for channel, platforms in _load_catalog().items():
        if not isinstance(platforms, dict):
            continue
        for platform, arches in platforms.items():
            if not isinstance(arches, dict):
                continue
            for arch, entry in arches.items():
                if not isinstance(entry, dict):
                    continue
                rows.append({
                    'channel': str(channel),
                    'platform': str(platform),
                    'arch': str(arch),
                    'filename': str(entry.get('filename') or ''),
                    'version': str(entry.get('version') or ''),
                    'notes': str(entry.get('notes') or ''),
                })
    return rows


def installer_rows() -> list[dict]:
    published: dict[str, dict] = {}
    for entry in published_entries():
        if entry['filename'] and entry['filename'] not in published:
            published[entry['filename']] = entry
    rows: list[dict] = []
    seen: set[str] = set()
    root = files_dir()
    paths = [path for path in root.iterdir() if path.is_file()] if root.is_dir() else []
    paths.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    for path in paths:
        if not _NAME.match(path.name):
            continue
        seen.add(path.name)
        stat = path.stat()
        entry = published.get(path.name)
        rows.append(_row(path.name, stat.st_size, stat.st_mtime, True, entry))
    for filename, entry in published.items():
        if filename in seen:
            continue
        rows.append(_row(filename, 0, None, False, entry))
    return rows


def _row(filename: str, size: int, mtime: float | None, on_disk: bool, entry: dict | None) -> dict:
    return {
        'filename': filename,
        'size': size,
        'size_label': format_bytes(size) if on_disk else '—',
        'modified': datetime.fromtimestamp(mtime).strftime('%d.%m.%Y %H:%M') if mtime else '—',
        'on_disk': on_disk,
        'current': entry is not None,
        'version': entry['version'] if entry else '',
        'notes': entry['notes'] if entry else '',
    }


def forget_filename(filename: str) -> bool:
    catalog = _load_catalog()
    changed = False
    for channel in list(catalog):
        platforms = catalog.get(channel)
        if not isinstance(platforms, dict):
            continue
        for platform in list(platforms):
            arches = platforms.get(platform)
            if not isinstance(arches, dict):
                continue
            for arch in list(arches):
                entry = arches.get(arch)
                if isinstance(entry, dict) and str(entry.get('filename') or '') == filename:
                    del arches[arch]
                    changed = True
            if not arches:
                del platforms[platform]
        if not platforms:
            del catalog[channel]
    if changed:
        _save_catalog(catalog)
    return changed


def delete_installer(filename: str) -> dict:
    target = _installer_path(filename)
    if target is None:
        raise HTTPException(status_code=404, detail='not found')
    removed_file = False
    if target.is_file():
        target.unlink()
        removed_file = True
    unpublished = forget_filename(filename)
    if not removed_file and not unpublished:
        raise HTTPException(status_code=404, detail='not found')
    return {'ok': True, 'filename': filename, 'removed_file': removed_file, 'unpublished': unpublished}


@router.get('/api/app/download/{filename}')
def download(filename: str) -> FileResponse:
    target = _installer_path(filename)
    if target is None or not target.is_file():
        raise HTTPException(status_code=404, detail='not found')
    return FileResponse(target, filename=filename, media_type='application/octet-stream')
