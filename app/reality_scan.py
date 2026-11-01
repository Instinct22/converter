from __future__ import annotations

from app.models import Node
from app.tls_sni import parse_dest
from app.xui import XuiClient, XuiError


def scan_target_on_node(node: Node, target: str, sni: str) -> dict:
    try:
        with XuiClient(node, timeout=15.0) as xui:
            payload = xui.scan_reality_target(target, sni)
    except XuiError as exc:
        return _row(node, error=str(exc))
    return _row(node, payload=payload)


def scan_view(name: str, node_id: int, payload: dict) -> dict:
    latency = int(payload.get('latencyMs') or 0)
    feasible = bool(payload.get('feasible'))
    return {
        'node_id': node_id,
        'name': name,
        'ok': True,
        'error': '',
        'latency_ms': latency,
        'feasible': feasible,
        'tls13': bool(payload.get('tls13')),
        'h2': bool(payload.get('h2')),
        'x25519': bool(payload.get('x25519')),
        'cert_valid': bool(payload.get('certValid')),
        'note': '' if feasible else _note(payload),
    }


def sort_scans(rows: list[dict]) -> list[dict]:
    def key(row: dict) -> tuple[int, int, str]:
        latency = row.get('latency_ms') or 0
        if row.get('ok') and latency:
            return (0, int(latency), row.get('name') or '')
        return (1, 10**9, row.get('name') or '')

    return sorted(rows, key=key)


def normalize_target(dest: str) -> str:
    host, port = parse_dest(dest)
    return f'{host}:{port}'


def _row(node: Node, payload: dict | None = None, error: str = '') -> dict:
    if error or payload is None:
        return {
            'node_id': node.id,
            'name': node.name,
            'ok': False,
            'error': error or 'проверка цели не удалась',
            'latency_ms': 0,
            'feasible': False,
            'tls13': False,
            'h2': False,
            'x25519': False,
            'cert_valid': False,
            'note': '',
        }
    view = scan_view(node.name, node.id or 0, payload)
    return view


def _note(payload: dict) -> str:
    reason = str(payload.get('reason') or '')
    low = reason.lower()
    if low.startswith('connection failed'):
        return 'нет соединения'
    if low.startswith('tls handshake failed'):
        return 'TLS не установился'
    parts: list[str] = []
    if payload.get('latencyMs') and not payload.get('tls13'):
        parts.append('нет TLS 1.3')
    if payload.get('latencyMs') and not payload.get('h2'):
        parts.append('нет HTTP/2')
    if payload.get('latencyMs') and not payload.get('x25519'):
        parts.append('нет X25519')
    if payload.get('latencyMs') and not payload.get('certValid'):
        parts.append('сертификат не подошёл')
    if parts:
        return ', '.join(parts)
    return reason or 'не подходит'
