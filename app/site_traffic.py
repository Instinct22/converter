"""Запросы к aegis-gate.ru из журнала Caddy.

РПС считается по всем строкам. Живым считается обычный браузер: пустой агент,
сканеры и известные роботы отбрасываются. Приток — первый заход такого
браузера с этого адреса. В базу попадает хеш, не сам адрес.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func
from sqlmodel import Session, delete, select

from app.models import SiteFirst, SiteLogCursor, SiteMinute, SiteSeen
from app.settings import DATA_DIR

LOG_DIR = DATA_DIR / 'caddy-access'
LOG_GLOB = 'aegis.log*'
KEEP_SECONDS = 14 * 24 * 3600
CHUNK = 2_000_000
BUDGET = 8_000_000
RANGES = {
    '1h': (3600, 60),
    '6h': (6 * 3600, 300),
    '24h': (24 * 3600, 900),
    '7d': (7 * 24 * 3600, 3600),
}

_LOCK = threading.Lock()
_BOT = re.compile(
    r'bot\b|spider|crawler|slurp|curl/|wget/|python-requests|python-urllib|'
    r'go-http-client|java/|libwww|scrapy|headless|phantomjs|selenium|puppeteer|'
    r'playwright|nuclei|zgrab|masscan|censys|shodan|ahrefs|semrush|dotbot|mj12|'
    r'petalbot|bytespider|gptbot|claudebot|amazonbot|applebot|bingbot|googlebot|'
    r'yandexbot|yandex\.com/bots|duckduckbot|baiduspider|facebookexternal|'
    r'twitterbot|telegrambot|whatsapp|slackbot|discordbot|linkedinbot|'
    r'uptimerobot|pingdom|lighthouse|httpx|aiohttp|fasthttp|okhttp|'
    r'dataprovider|expanse|netcraft|archive\.org|ia_archiver|serpstat|'
    r'megaindex|blexbot|sogou|exabot|libcurl|axios/|node-fetch|undici|colly',
    re.I,
)
_ASSET = re.compile(
    r'\.(?:css|js|mjs|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|mp4|webmanifest)(?:$|\?)',
    re.I,
)


def is_bot(user_agent: str) -> bool:
    text = (user_agent or '').strip()
    if not text or 'mozilla/' not in text.lower():
        return True
    return _BOT.search(text) is not None


def is_page(uri: str) -> bool:
    path = (uri or '/').split('?', 1)[0]
    if _ASSET.search(path):
        return False
    if path.startswith('/api/') or path.startswith('/auth/'):
        return False
    return True


def browser_family(user_agent: str) -> str:
    text = (user_agent or '').lower()
    if 'edg/' in text:
        return 'edge'
    if 'yabrowser' in text:
        return 'yandex'
    if 'opr/' in text or 'opera' in text:
        return 'opera'
    if 'firefox/' in text or 'fxios/' in text:
        return 'firefox'
    if 'chrome/' in text or 'crios/' in text:
        return 'chrome'
    if 'safari/' in text:
        return 'safari'
    return 'other'


def _salt() -> bytes:
    path = DATA_DIR / 'site_visitor_salt'
    if path.is_file():
        stored = path.read_bytes().strip()
        if stored:
            return stored
    path.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_hex(16).encode()
    path.write_bytes(salt)
    return salt


def visitor_id(ip: str, user_agent: str, salt: bytes | None = None) -> str:
    key = salt if salt is not None else _salt()
    raw = f'{ip}|{browser_family(user_agent)}'.encode()
    return hmac.new(key, raw, hashlib.sha256).hexdigest()[:16]


def format_rps(value: float) -> str:
    if value <= 0:
        return '0'
    if value >= 10:
        return f'{value:.1f}'
    if value >= 1:
        return f'{value:.2f}'
    return f'{value:.3f}'


def _header(headers: object, name: str) -> str:
    if not isinstance(headers, dict):
        return ''
    for key, value in headers.items():
        if str(key).lower() != name:
            continue
        if isinstance(value, list):
            return str(value[0] if value else '')
        return str(value or '')
    return ''


def parse_hit(line: str, now: int | None = None) -> dict | None:
    """Одна строка JSON-журнала Caddy. None — строку пропускаем."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    request = payload.get('request')
    if not isinstance(request, dict):
        return None
    stamp = payload.get('ts')
    if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
        return None
    moment = int(stamp)
    current = now if now is not None else int(datetime.now(timezone.utc).timestamp())
    if moment < current - KEEP_SECONDS or moment > current + 120:
        return None
    host = str(request.get('host') or '')
    if host and host.split(':', 1)[0].lower() not in {'aegis-gate.ru', 'www.aegis-gate.ru'}:
        return None
    agent = _header(request.get('headers'), 'user-agent')
    human = not is_bot(agent)
    ip = str(request.get('client_ip') or request.get('remote_ip') or '').strip()
    uri = str(request.get('uri') or '/')
    visitor = ''
    if human and ip and is_page(uri):
        visitor = visitor_id(ip, agent)
    return {'minute': moment - moment % 60, 'human': human, 'visitor': visitor}


def _file_key(path: Path) -> str:
    stat = path.stat()
    return f'{stat.st_dev}:{stat.st_ino}'


def ingest_access_log(session: Session, directory: Path | None = None, now: int | None = None) -> int:
    """Дочитать новые строки журнала. Повторный вызов те же строки не считает."""
    folder = directory or LOG_DIR
    if not _LOCK.acquire(blocking=False):
        return 0
    try:
        if not folder.is_dir():
            return 0
        current = now if now is not None else int(datetime.now(timezone.utc).timestamp())
        taken = 0
        budget = BUDGET
        for path in sorted(folder.glob(LOG_GLOB)):
            if budget <= 0 or path.suffix == '.gz' or not path.is_file():
                continue
            taken += _ingest_file(session, path, current, budget)
            budget = BUDGET - taken
        _purge(session, current)
        session.commit()
        return taken
    finally:
        _LOCK.release()


def _ingest_file(session: Session, path: Path, now: int, budget: int) -> int:
    key = _file_key(path)
    cursor = session.get(SiteLogCursor, key)
    offset = cursor.offset if cursor is not None else 0
    size = path.stat().st_size
    if size < offset:
        offset = 0
    if size == offset:
        return 0
    with path.open('rb') as handle:
        handle.seek(offset)
        raw = handle.read(min(CHUNK, budget))
    cut = raw.rfind(b'\n')
    if cut < 0:
        return 0
    chunk = raw[:cut + 1]
    hits: list[dict] = []
    for line in chunk.decode('utf-8', 'replace').splitlines():
        if not line.strip():
            continue
        hit = parse_hit(line, now)
        if hit is not None:
            hits.append(hit)
    _store_hits(session, hits)
    if cursor is None:
        cursor = SiteLogCursor(file_key=key, offset=offset + cut + 1)
    else:
        cursor.offset = offset + cut + 1
    session.add(cursor)
    return len(chunk)


def _store_hits(session: Session, hits: list[dict]) -> None:
    if not hits:
        return
    minutes = {hit['minute'] for hit in hits}
    rows = {
        row.minute: row
        for row in session.exec(select(SiteMinute).where(SiteMinute.minute.in_(minutes))).all()
    }
    seen_minutes = {hit['minute'] for hit in hits if hit['visitor']}
    known = {
        (row.minute, row.visitor)
        for row in session.exec(select(SiteSeen).where(SiteSeen.minute.in_(seen_minutes or {-1}))).all()
    }
    fresh: set[tuple[int, str]] = set()
    born: set[str] = set()
    for hit in hits:
        row = rows.get(hit['minute'])
        if row is None:
            row = SiteMinute(minute=hit['minute'], requests=0, human_requests=0)
            rows[hit['minute']] = row
            session.add(row)
        row.requests += 1
        if hit['human']:
            row.human_requests += 1
        visitor = hit['visitor']
        if not visitor:
            continue
        pair = (hit['minute'], visitor)
        if pair in known or pair in fresh:
            continue
        fresh.add(pair)
        session.add(SiteSeen(minute=hit['minute'], visitor=visitor))
        if visitor in born or session.get(SiteFirst, visitor) is not None:
            continue
        born.add(visitor)
        session.add(SiteFirst(visitor=visitor, minute=hit['minute']))


def _purge(session: Session, now: int) -> None:
    cutoff = now - KEEP_SECONDS
    session.exec(delete(SiteMinute).where(SiteMinute.minute < cutoff))
    session.exec(delete(SiteSeen).where(SiteSeen.minute < cutoff))


def site_metrics(session: Session, now: int) -> list[str]:
    """Завершённые минуты из тех же агрегатов, что на вкладке «Сайт»."""
    end = now - now % 60
    start = end - 300
    log = LOG_DIR / 'aegis.log'
    try:
        cursor = session.get(SiteLogCursor, _file_key(log))
        lag = max(0, log.stat().st_size - (cursor.offset if cursor else 0))
    except OSError:
        return ['master_site_log_available 0']
    lines = ['master_site_log_available 1', f'master_site_log_unread_bytes {lag}']
    requests, browsers = session.exec(
        select(func.sum(SiteMinute.requests), func.sum(SiteMinute.human_requests))
        .where(SiteMinute.minute >= start, SiteMinute.minute < end)
    ).one()
    lines.extend([
        f'master_site_requests_per_second {(requests or 0) / 300}',
        f'master_site_browser_requests_per_second {(browsers or 0) / 300}',
    ])
    active = session.exec(select(func.count(func.distinct(SiteSeen.visitor))).where(
        SiteSeen.minute >= start, SiteSeen.minute < end)).one()
    lines.append(f'master_site_active_visitors_5m {active}')
    for seconds, window in ((300, '5m'), (86400, '24h')):
        fresh = session.exec(select(func.count()).select_from(SiteFirst).where(
            SiteFirst.minute >= end - seconds, SiteFirst.minute < end)).one()
        lines.append(f'master_site_new_visitors{{window="{window}"}} {fresh}')
    return lines


def site_series(session: Session, span: str, now: datetime | None = None) -> dict:
    if span not in RANGES:
        span = '24h'
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    current = int(moment.timestamp())
    window, step = RANGES[span]
    start = current - window
    start -= start % step
    buckets: list[int] = []
    cursor = start
    while cursor <= current:
        buckets.append(cursor)
        cursor += step
    minutes = session.exec(select(SiteMinute).where(SiteMinute.minute >= start)).all()
    seen = session.exec(select(SiteSeen).where(SiteSeen.minute >= start)).all()
    firsts = session.exec(select(SiteFirst).where(SiteFirst.minute >= start)).all()
    requests = {bucket: [0, 0] for bucket in buckets}
    for row in minutes:
        bucket = row.minute - row.minute % step
        if bucket not in requests:
            continue
        requests[bucket][0] += row.requests
        requests[bucket][1] += row.human_requests
    active: dict[int, set[str]] = {bucket: set() for bucket in buckets}
    for row in seen:
        bucket = row.minute - row.minute % step
        if bucket in active:
            active[bucket].add(row.visitor)
    fresh: dict[int, int] = {bucket: 0 for bucket in buckets}
    newcomers: set[str] = set()
    for row in firsts:
        if row.minute > current:
            continue
        bucket = row.minute - row.minute % step
        if bucket in fresh:
            fresh[bucket] += 1
            newcomers.add(row.visitor)
    rps_points = []
    people_points = []
    total_requests = 0
    total_human = 0
    for bucket in buckets:
        elapsed = step
        if bucket + step > current:
            elapsed = max(1, current - bucket)
        all_count, human_count = requests[bucket]
        total_requests += all_count
        total_human += human_count
        rps_points.append({
            't': bucket,
            'all': all_count / elapsed,
            'human': human_count / elapsed,
        })
        people_points.append({
            't': bucket,
            'active': len(active[bucket]),
            'new': fresh[bucket],
        })
    elapsed_window = max(1, current - start)
    collecting = _collecting()
    return {
        'span': span,
        'step': step,
        'collecting': collecting,
        'samples': total_requests,
        'rps': {
            'now': rps_points[-1]['all'] if rps_points else 0,
            'now_human': rps_points[-1]['human'] if rps_points else 0,
            'avg': total_requests / elapsed_window,
            'avg_human': total_human / elapsed_window,
            'now_label': format_rps(rps_points[-1]['all'] if rps_points else 0),
            'avg_label': format_rps(total_requests / elapsed_window),
            'points': rps_points,
        },
        'people': {
            'unique': len({row.visitor for row in seen}),
            'new': len(newcomers),
            'points': people_points,
        },
    }


def _collecting() -> bool:
    if not LOG_DIR.is_dir():
        return False
    return any(path.is_file() and path.stat().st_size > 0 for path in LOG_DIR.glob(LOG_GLOB))
