"""Сводки пинга, которые приложения присылают сами.

«Из РФ» — это мастер стучится в порт ноды. Здесь другое: люди уже прошли
рукопожатие до сервера и прислали, сколько это заняло.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from typing import Any

from sqlmodel import Session, select

from app.flags import country_name, flag_src
from app.mihomo import is_expired
from app.models import Client, ClientPingReport, Node, NodePingHour, utcnow

_FLAG = re.compile(r'[\U0001F1E6-\U0001F1FF]+')
_MAX_SERVERS = 64
_SAMPLE_CAP = 500
_KEEP_SAMPLES = timedelta(days=14)
_KEEP_HOURS = timedelta(days=90)
_REASONS = {
    'handshake': 'блок рукопожатия',
    'unreachable': 'IP недоступен',
    'no-response': 'сервер не отвечает',
    'timeout': 'долгий ответ',
    'error': 'ошибка проверки',
    'missing': 'ошибка проверки',
}
_recent: dict[str, datetime] = {}
_GAP = timedelta(seconds=20)
_MOSCOW = ZoneInfo('Europe/Moscow')


def normalize_server(label: str) -> str:
    text = _FLAG.sub('', label or '')
    cleaned = ''.join(ch for ch in text if ch.isalnum() or ch in '- ')
    return ' '.join(cleaned.lower().split())


def percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * fraction
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] * (1 - (rank - low)) + ordered[high] * (rank - low))


def reason_label(reason: str) -> str:
    return _REASONS.get(reason, reason or 'ошибка проверки')


def floor_hour(moment: datetime) -> datetime:
    moment = _aware(moment)
    return moment.replace(minute=0, second=0, microsecond=0)


def _aware(moment: datetime) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _node_index(nodes: list[Node]) -> dict[str, Node]:
    index: dict[str, Node] = {}
    for node in nodes:
        for raw in (node.clash_name, node.name, node.clash_prefix()):
            key = normalize_server(raw)
            if key and key not in index:
                index[key] = node
    return index


def _leading_flag(label: str) -> tuple[str, str]:
    text = (label or '').strip()
    if len(text) >= 2 and all('\U0001F1E6' <= ch <= '\U0001F1FF' for ch in text[:2]):
        return text[:2], text[2:].lstrip()
    return '', text


def _match_node(label: str, index: dict[str, Node]) -> Node | None:
    key = normalize_server(label)
    if not key:
        return None
    found = index.get(key)
    if found is not None:
        return found
    best_key = ''
    best: Node | None = None
    for node_key, node in index.items():
        if node_key and key.startswith(node_key + ' ') and len(node_key) > len(best_key):
            best_key = node_key
            best = node
    return best


def server_faces(nodes: list[Node]):
    """Имя туннеля без эмодзи и картинка флага, как на остальных страницах."""
    index = _node_index(list(nodes))

    def face(label: str) -> dict[str, str]:
        emoji, name = _leading_flag(label or '')
        node = _match_node(label or '', index)
        if node is not None and node.flag_image():
            flag = node.flag_image()
            title = node.flag_title()
        elif emoji:
            flag = flag_src(emoji)
            title = country_name(emoji)
        else:
            flag = ''
            title = ''
        return {'name': name or (label or '').strip() or '—', 'flag': flag, 'title': title}

    return face


def _clip(value: Any, limit: int) -> str:
    return str(value or '').strip()[:limit]


def _int(value: Any, upper: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 0 or value > upper:
        return None
    return value


def parse_report(payload: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    servers = payload.get('servers')
    if not isinstance(servers, list) or not servers or len(servers) > _MAX_SERVERS:
        return None
    rows: list[dict[str, Any]] = []
    for item in servers:
        if not isinstance(item, dict):
            return None
        server = _clip(item.get('server'), 80)
        if not server:
            return None
        median = item.get('median_ms')
        if median is not None:
            median = _int(median, 60_000)
            if median is None or median == 0:
                return None
        ok = _int(item.get('ok'), 1000)
        failed = _int(item.get('failed'), 1000)
        if ok is None or failed is None or ok + failed == 0:
            return None
        if ok > 0 and median is None:
            return None
        reason = _clip(item.get('reason'), 32)
        if reason and reason not in _REASONS:
            reason = 'error'
        at = _parse_time(item.get('at'), now)
        rows.append(
            {
                'server': server,
                'median_ms': median,
                'ok': ok,
                'failed': failed,
                'reason': reason,
                'at': at.isoformat(),
            }
        )
    return {
        'app_version': _clip(payload.get('app_version'), 32),
        'platform': _clip(payload.get('platform'), 32),
        'exit_server': _clip(payload.get('exit_server'), 80),
        'servers': rows,
    }


def _parse_time(value: Any, now: datetime) -> datetime:
    if not isinstance(value, str):
        return now
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return now
    parsed = _aware(parsed)
    if parsed > now + timedelta(minutes=5) or now - parsed > timedelta(hours=24):
        return now
    return parsed


def _limited(token: str, now: datetime) -> bool:
    last = _recent.get(token)
    if last is not None and now - last < _GAP:
        return True
    _recent[token] = now
    return False


def ingest_report(session: Session, token: str, payload: dict[str, Any], now: datetime | None = None) -> str:
    """'ok', 'limited', 'unknown', 'expired' or 'bad'."""
    moment = _aware(now or utcnow())
    client = session.exec(select(Client).where(Client.sub_token == token)).first()
    if client is None or client.id is None:
        return 'unknown'
    if is_expired(client):
        return 'expired'
    if _limited(token, moment):
        return 'limited'
    parsed = parse_report(payload, moment)
    if parsed is None:
        return 'bad'
    report = session.get(ClientPingReport, client.id)
    if report is None:
        report = ClientPingReport(client_id=client.id)
    report.seen_at = moment
    report.app_version = parsed['app_version']
    report.platform = parsed['platform']
    report.exit_server = parsed['exit_server']
    report.servers_json = json.dumps(parsed['servers'], ensure_ascii=False)
    session.add(report)
    nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
    index = _node_index(nodes)
    hour = floor_hour(moment)
    for row in parsed['servers']:
        node = _match_node(row['server'], index)
        if node is None or node.id is None:
            continue
        _add_hour(session, node.id, hour, row)
    session.commit()
    return 'ok'


def _add_hour(session: Session, node_id: int, hour: datetime, row: dict[str, Any]) -> None:
    current = session.exec(
        select(NodePingHour).where(NodePingHour.node_id == node_id, NodePingHour.hour == hour)
    ).first()
    if current is None:
        current = NodePingHour(node_id=node_id, hour=hour)
    samples = _load_list(current.samples_json)
    reasons = _load_map(current.reasons_json)
    current.reports += 1
    if row['failed'] > 0:
        reason = row['reason'] or 'error'
        reasons[reason] = int(reasons.get(reason, 0)) + 1
    if row['ok'] == 0:
        current.fails += 1
    elif isinstance(row['median_ms'], int):
        samples.append(row['median_ms'])
        del samples[:-_SAMPLE_CAP]
    current.samples_json = json.dumps(samples)
    current.reasons_json = json.dumps(reasons)
    session.add(current)


def _load_list(raw: str) -> list[int]:
    try:
        loaded = json.loads(raw or '[]')
    except json.JSONDecodeError:
        return []
    if not isinstance(loaded, list):
        return []
    return [int(item) for item in loaded if isinstance(item, int)]


def _load_map(raw: str) -> dict[str, int]:
    try:
        loaded = json.loads(raw or '{}')
    except json.JSONDecodeError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return {str(key): int(value) for key, value in loaded.items() if isinstance(value, int)}


def _view(row: NodePingHour) -> dict[str, Any]:
    samples = _load_list(row.samples_json)
    reports = row.reports or 0
    return {
        'reports': reports,
        'fails': row.fails,
        'fail_rate': round(100 * row.fails / reports) if reports else 0,
        'median': percentile(samples, 0.5),
        'p90': percentile(samples, 0.9),
        'reasons': _load_map(row.reasons_json),
    }


def recent_nodes(session: Session, now: datetime | None = None) -> list[dict[str, Any]]:
    moment = _aware(now or utcnow())
    start = floor_hour(moment) - timedelta(hours=1)
    rows = session.exec(select(NodePingHour).where(NodePingHour.hour >= start)).all()
    by_node: dict[int, list[NodePingHour]] = {}
    for row in rows:
        by_node.setdefault(row.node_id, []).append(row)
    nodes = session.exec(select(Node).where(Node.enabled.is_(True)).order_by(Node.sort_order, Node.id)).all()
    result = []
    for node in nodes:
        if node.id is None:
            continue
        merged = _merge(by_node.get(node.id, []))
        result.append({'node': node, **merged})
    result.sort(key=lambda item: (-(item['fail_rate'] or 0), item['node'].name))
    return result


def _merge(rows: list[NodePingHour]) -> dict[str, Any]:
    if not rows:
        return {'reports': 0, 'fails': 0, 'fail_rate': 0, 'median': None, 'p90': None, 'reasons': {}}
    samples: list[int] = []
    reasons: dict[str, int] = {}
    reports = 0
    fails = 0
    for row in rows:
        view = _view(row)
        samples.extend(_load_list(row.samples_json))
        reports += view['reports']
        fails += view['fails']
        for key, count in view['reasons'].items():
            reasons[key] = reasons.get(key, 0) + count
    return {
        'reports': reports,
        'fails': fails,
        'fail_rate': round(100 * fails / reports) if reports else 0,
        'median': percentile(samples, 0.5),
        'p90': percentile(samples, 0.9),
        'reasons': reasons,
    }


def node_day(session: Session, node_id: int, now: datetime | None = None) -> list[dict[str, Any]]:
    moment = floor_hour(_aware(now or utcnow()))
    start = moment - timedelta(hours=23)
    rows = session.exec(
        select(NodePingHour).where(NodePingHour.node_id == node_id, NodePingHour.hour >= start)
    ).all()
    by_hour = {_aware(row.hour): row for row in rows}
    series = []
    for step in range(24):
        hour = start + timedelta(hours=step)
        row = by_hour.get(hour)
        series.append(
            {
                'hour': hour,
                'median': _view(row)['median'] if row else None,
                'reports': row.reports if row else 0,
            }
        )
    return series


def node_reasons(session: Session, node_id: int, now: datetime | None = None) -> list[tuple[str, int]]:
    moment = floor_hour(_aware(now or utcnow()))
    start = moment - timedelta(hours=23)
    rows = session.exec(
        select(NodePingHour).where(NodePingHour.node_id == node_id, NodePingHour.hour >= start)
    ).all()
    totals: dict[str, int] = {}
    for row in rows:
        for key, count in _view(row)['reasons'].items():
            totals[key] = totals.get(key, 0) + count
    return sorted(totals.items(), key=lambda item: -item[1])


def recent_clients(session: Session) -> list[tuple[Client, ClientPingReport]]:
    rows = session.exec(select(ClientPingReport).order_by(ClientPingReport.seen_at.desc())).all()
    paired: list[tuple[Client, ClientPingReport]] = []
    for report in rows[:50]:
        client = session.get(Client, report.client_id)
        if client is not None:
            paired.append((client, report))
    return paired


def as_moscow(moment: datetime) -> str:
    return _aware(moment).astimezone(_MOSCOW).strftime('%d.%m %H:%M')


def epoch(moment: datetime) -> int:
    return int(_aware(moment).timestamp())


def _probe_counts(row: dict[str, Any]) -> tuple[int, int]:
    ok = row.get('ok') or 0
    failed = row.get('failed') or 0
    if isinstance(ok, bool) or not isinstance(ok, int):
        ok = 0
    if isinstance(failed, bool) or not isinstance(failed, int):
        failed = 0
    return ok, failed


def _median_ms(row: dict[str, Any]) -> int | None:
    value = row.get('median_ms')
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _stored_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return _aware(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _aware(datetime.fromisoformat(value.replace('Z', '+00:00')))
    except ValueError:
        return None


def classify_server(row: dict[str, Any]) -> dict[str, Any]:
    """Как туннель выглядел в одной книге: открылся, открылся с отказами или нет."""
    ok, failed = _probe_counts(row)
    reason = str(row.get('reason') or '')
    if ok > 0 and failed == 0:
        label, tone, rank, key = 'доступен', 'ok', 0, 'ok'
    elif ok > 0:
        detail = reason_label(reason) if reason else ''
        label = f'с отказами · {detail}' if detail else 'с отказами'
        tone, rank, key = 'warn', 1, 'partial:' + (reason or 'error')
    else:
        label = reason_label(reason) if reason else 'недоступен'
        tone, rank, key = 'bad', 2, 'down:' + (reason or 'error')
    return {'key': key, 'label': label, 'tone': tone, 'rank': rank, 'sort': f'{rank} {label}'}


def _rate_tone(rate: int) -> str:
    if rate >= 100:
        return 'ok'
    if rate <= 0:
        return 'bad'
    return 'warn'


def availability_counts(report: ClientPingReport) -> dict[str, int]:
    available = 0
    unavailable = 0
    for row in report_servers(report):
        ok, failed = _probe_counts(row)
        if ok > 0:
            available += 1
        elif failed > 0:
            unavailable += 1
    return {'available': available, 'unavailable': unavailable}


def report_servers(report: ClientPingReport) -> list[dict[str, Any]]:
    try:
        loaded = json.loads(report.servers_json or '[]')
    except json.JSONDecodeError:
        return []
    if not isinstance(loaded, list):
        return []
    return [item for item in loaded if isinstance(item, dict)]


def node_reporters(session: Session, node_id: int) -> list[dict[str, Any]]:
    """Последняя книга каждого клиента, в которой встретился этот сервер.

    В книге может быть несколько туннелей одной ноды — каждая строка отдельно.
    """
    nodes = list(session.exec(select(Node)).all())
    index = _node_index(nodes)
    face = server_faces(nodes)
    reports = session.exec(select(ClientPingReport).order_by(ClientPingReport.seen_at.desc())).all()
    found: list[dict[str, Any]] = []
    for report in reports:
        client = session.get(Client, report.client_id)
        if client is None:
            continue
        seen = _aware(report.seen_at)
        exit_node = _match_node(report.exit_server, index)
        for row in report_servers(report):
            label = str(row.get('server') or '')
            matched = _match_node(label, index)
            if matched is None or matched.id != node_id:
                continue
            ok, failed = _probe_counts(row)
            measured = _stored_time(row.get('at')) or seen
            found.append(
                {
                    'client': client,
                    'face': face(label),
                    'status': classify_server(row),
                    'measured': measured,
                    'seen': seen,
                    'measured_ts': int(measured.timestamp()),
                    'seen_ts': int(seen.timestamp()),
                    'median': _median_ms(row),
                    'ok': ok,
                    'failed': failed,
                    'platform': report.platform,
                    'app_version': report.app_version,
                    'exit_here': exit_node is not None and exit_node.id == node_id,
                }
            )
    found.sort(key=lambda item: item['measured'], reverse=True)
    return found


def reporter_buckets(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        status = row['status']
        bucket = grouped.get(status['key'])
        if bucket is None:
            bucket = {
                'key': status['key'],
                'label': status['label'],
                'tone': status['tone'],
                'rank': status['rank'],
                'count': 0,
            }
            grouped[status['key']] = bucket
        bucket['count'] += 1
    return sorted(grouped.values(), key=lambda item: (item['rank'], -item['count'], item['label']))


def client_server_chart(session: Session, report: ClientPingReport) -> dict[str, Any]:
    """Полосы последней книги: задержка и доля успешных проб по каждому туннелю."""
    nodes = list(session.exec(select(Node)).all())
    index = _node_index(nodes)
    face = server_faces(nodes)
    drafted: list[dict[str, Any]] = []
    medians: list[int] = []
    for row in report_servers(report):
        label = str(row.get('server') or '')
        ok, failed = _probe_counts(row)
        median = _median_ms(row)
        total = ok + failed
        rate = round(100 * ok / total) if total else 0
        matched = _match_node(label, index)
        if median is not None:
            medians.append(median)
        drafted.append(
            {
                'face': face(label),
                'status': classify_server(row),
                'median': median,
                'ok': ok,
                'failed': failed,
                'rate': rate,
                'rate_tone': _rate_tone(rate),
                'href': f'/pings/node/{matched.id}' if matched is not None and matched.id is not None else '',
            }
        )
    peak = max(medians) if medians else 1
    for item in drafted:
        median = item['median']
        item['latency_pct'] = max(4, round(100 * median / peak)) if isinstance(median, int) else 0
    latency = sorted((item for item in drafted if item['median'] is not None), key=lambda item: item['median'], reverse=True)
    return {'rows': drafted, 'latency': latency}


def purge_old_ping_hours(session: Session, now: datetime | None = None) -> None:
    moment = _aware(now or utcnow())
    rows = session.exec(select(NodePingHour)).all()
    for row in rows:
        hour = _aware(row.hour)
        if hour < moment - _KEEP_HOURS:
            session.delete(row)
            continue
        if hour < moment - _KEEP_SAMPLES and not row.rolled:
            median = percentile(_load_list(row.samples_json), 0.5)
            row.samples_json = json.dumps([median] if median is not None else [])
            row.rolled = True
            session.add(row)
    session.commit()
