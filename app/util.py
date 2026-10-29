from __future__ import annotations

import re
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone


def new_uuid() -> str:
    return str(uuid.uuid4())


def new_token(length: int = 16) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def slugify(name: str) -> str:
    slug = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')
    return (slug or 'user')[:40]


def ru_days(n: int) -> str:
    abs_n = abs(int(n))
    if 11 <= abs_n % 100 <= 14:
        word = 'дней'
    else:
        rem = abs_n % 10
        if rem == 1:
            word = 'день'
        elif rem in {2, 3, 4}:
            word = 'дня'
        else:
            word = 'дней'
    return f'{n} {word}'


def expire_from_days(days: int) -> datetime | None:
    if days <= 0:
        return None
    return datetime.now(timezone.utc) + timedelta(days=days)


def format_bytes(n: int | float | None) -> str:
    value = float(n or 0)
    units = ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ')
    idx = 0
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    if idx == 0:
        return f'{int(value)} {units[idx]}'
    return f'{value:.1f} {units[idx]}'


def cpu_percent(value: object) -> int | None:
    if value is None or value == '':
        return None
    try:
        num = float(value)
    except (TypeError, ValueError):
        return None
    if num <= 1.5:
        return int(round(num * 100))
    return int(round(num))
