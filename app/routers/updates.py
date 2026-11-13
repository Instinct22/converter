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

from app.settings import DATA_DIR, ROOT, settings
from app.util import format_bytes

router = APIRouter()

_NAME = re.compile(r'^AegisGate-[A-Za-z0-9._-]+$')
_SHA = re.compile(r'^[0-9a-fA-F]{64}$')
_WINDOWS = re.compile(r'^AegisGate-(.+)-windows-amd64-setup\.exe$')
_ANDROID = re.compile(r'^AegisGate-(.+)-android-(arm64|arm|x64)\.apk$')
_KIND_ORDER = {'Windows': 0, 'Android arm64': 1, 'Android arm': 2, 'Android x64': 3}


def catalog_path() -> Path:
    return DATA_DIR / 'updates' / 'catalog.json'


def files_dir() -> Path:
    return DATA_DIR / 'updates' / 'files'


def notes_path() -> Path:
    return catalog_path().parent / 'release-notes.json'


def seed_notes() -> dict[str, str]:
    path = ROOT / 'app' / 'release_notes_seed.json'
    if not path.is_file():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {str(key): str(value).strip() for key, value in loaded.items() if str(value).strip()}


def load_version_notes() -> dict[str, str]:
    path = notes_path()
    saved: dict[str, str] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            loaded = {}
        if isinstance(loaded, dict):
            saved = {str(key): str(value).strip() for key, value in loaded.items() if str(value).strip()}
    for version, notes in seed_notes().items():
        saved.setdefault(version, notes)
    return saved


def remember_version_notes(found: dict[str, str]) -> None:
    if not found:
        return
    path = notes_path()
    current: dict[str, str] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError):
            loaded = {}
        if isinstance(loaded, dict):
            current = {str(key): str(value) for key, value in loaded.items()}
    changed = False
    for version, notes in found.items():
        text = notes.strip()
        if version and text and current.get(version) != text:
            current[version] = text
            changed = True
    if not changed:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(current, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def _signatures(entry: dict) -> list[str]:
    found: list[str] = []
    raw = entry.get('signatures')
    if isinstance(raw, list):
        for item in raw:
            text = item.strip() if isinstance(item, str) else ''
            if text and text not in found:
                found.append(text)
    single = entry.get('signature')
    if isinstance(single, str):
        text = single.strip()
        if text and text not in found:
            found.insert(0, text)
    return found


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
    body = {
        'update': True,
        'version': version,
        'notes': str(entry.get('notes') or ''),
        'url': f'{base}/api/app/download/{filename}',
        'filename': filename,
        'sha256': sha256,
    }
    signatures = _signatures(entry)
    if signatures:
        body['signature'] = signatures[0]
        body['signatures'] = signatures
    return body


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


def note_blocks(text: str) -> list[dict]:
    blocks: list[dict] = []
    items: list[str] = []

    def flush() -> None:
        if items:
            blocks.append({'type': 'list', 'items': items.copy()})
            items.clear()

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            flush()
            continue
        if line.startswith(('- ', '* ', '• ')):
            items.append(line[2:].strip())
            continue
        flush()
        blocks.append({'type': 'text', 'text': line})
    flush()
    return blocks


def file_release(filename: str) -> tuple[str, str]:
    windows = _WINDOWS.match(filename)
    if windows:
        return windows.group(1), 'Windows'
    android = _ANDROID.match(filename)
    if android:
        kind = {'arm64': 'Android arm64', 'arm': 'Android arm', 'x64': 'Android x64'}[android.group(2)]
        return android.group(1), kind
    return '', ''


def _version_key(version: str) -> tuple:
    pieces = re.findall(r'\d+|[A-Za-z]+', version)
    has_name = any(not piece.isdigit() for piece in pieces)
    chunks = tuple((0, int(piece)) if piece.isdigit() else (1, piece) for piece in pieces)
    return (0 if has_name else 1, chunks)


def release_groups() -> list[dict]:
    saved = load_version_notes()
    fresh: dict[str, str] = {}
    groups: dict[str, dict] = {}
    for row in installer_rows():
        version, kind = file_release(row['filename'])
        key = version or row['filename']
        group = groups.get(key)
        if group is None:
            group = {
                'version': key,
                'known': bool(version),
                'notes': '',
                'current': False,
                'files': [],
            }
            groups[key] = group
        notes = row['notes'] or saved.get(version, '')
        if row['notes'] and version:
            fresh[version] = row['notes']
        if notes and not group['notes']:
            group['notes'] = notes
        group['current'] = group['current'] or bool(row['current'])
        group['files'].append({**row, 'kind': kind or 'Файл', 'own_notes': notes})
    for version, notes in saved.items():
        if version not in fresh:
            fresh.setdefault(version, notes)
    remember_version_notes(fresh)
    ordered = sorted(groups.values(), key=lambda group: (group['known'], _version_key(group['version'])), reverse=True)
    for group in ordered:
        shared = group['notes']
        same = all(not item['own_notes'] or item['own_notes'] == shared for item in group['files'])
        if not same:
            group['notes'] = ''
        group['blocks'] = note_blocks(group['notes'])
        for item in group['files']:
            item['show_notes'] = bool(item['own_notes']) and item['own_notes'] != group['notes']
            item['blocks'] = note_blocks(item['own_notes']) if item['show_notes'] else []
        group['files'].sort(key=lambda item: (_KIND_ORDER.get(item['kind'], 9), item['filename']))
    return ordered


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
