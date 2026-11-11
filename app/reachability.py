"""Виден ли сервер клиентам из России.

Мастер стоит в РФ, поэтому TCP-соединение к портам входов прямо отсюда —
это и есть ответ на вопрос «доходит ли нода до российских клиентов».
Панель 3x-ui при этом остаётся зелёной: у неё свой порт, и он отвечает.

Порты входов (443 и остальные) SSH не трогают, а мастер внесён в ignoreip
fail2ban, так что прообы бан не наживают. Проверка только TCP: обрыв на ClientHello по SNI так не увидеть.
Зато видно, когда порт приняли не сервером: панель или SSH того же
адреса отвечают за десятки миллисекунд, а 443 открывается мгновенно.

Важно для локального запуска: если на машине мастера поднят TUN/VPN
(Mihomo, WireGuard, Radmin), он может принимать соединения на любые адреса —
такая машина даёт ложное «есть». На боевом мастере (VPS в РФ, контейнер без
TUN) прообы честные.
"""
from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urlparse

from sqlmodel import Session, select

from app.models import Node, NodeInbound, utcnow

TIMEOUT = 4.0
_NOTE_LIMIT = 500
# Хост далеко, если ориентир (панель или SSH) не быстрее этого.
_FAR_MS = 10
# Быстрее этого при далёком ориентире соединение принял не сервер.
_INSTANT_MS = 2


def node_host(node: Node) -> str:
    """Адрес, которым пользуется клиент: public_host, иначе хост панели."""
    host = (node.public_host or '').strip()
    if host:
        return host
    parsed = urlparse((node.panel_url or '').strip())
    return parsed.hostname or ''


def inbound_ports(session: Session, node_id: int) -> list[int]:
    """Порты входов ноды, которые выдаются в подписке."""
    rows = session.exec(
        select(NodeInbound).where(NodeInbound.node_id == node_id)
    ).all()
    return [int(row.port) for row in rows if row.use_in_sub and int(row.port or 0) > 0]


def clean_ports(ports: list[int]) -> list[int]:
    return sorted({int(port) for port in ports if int(port or 0) > 0})


def panel_port(node: Node) -> int:
    parsed = urlparse((node.panel_url or '').strip())
    if parsed.port:
        return int(parsed.port)
    if parsed.scheme == 'https':
        return 443
    if parsed.scheme == 'http':
        return 80
    return 0


def reference_port(node: Node, ports: list[int]) -> int:
    """Порт не из подписки: по нему видно настоящую задержку до машины."""
    used = set(ports)
    ssh = int(node.ssh_port or 0)
    for port in (panel_port(node), ssh):
        if port > 0 and port not in used:
            return port
    return 0


def accepted_elsewhere(ms: int, reference_ms: int | None) -> bool:
    """TCP открылся слишком быстро для машины, до которой ориентир идёт долго."""
    if reference_ms is None or reference_ms < _FAR_MS:
        return False
    return int(ms) <= _INSTANT_MS


def probe_port(host: str, port: int, timeout: float = TIMEOUT) -> dict[str, Any]:
    """Одно TCP-соединение из России к порту ноды."""
    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return {
                'port': int(port),
                'ok': True,
                'ms': int((time.monotonic() - started) * 1000),
                'error': '',
            }
    except socket.timeout:
        note = 'нет ответа'
        return {'port': int(port), 'ok': False, 'ms': _elapsed_ms(started), 'error': note}
    except socket.gaierror:
        return {'port': int(port), 'ok': False, 'ms': 0, 'error': 'адрес не разобрался'}
    except OSError as exc:
        return {
            'port': int(port),
            'ok': False,
            'ms': _elapsed_ms(started),
            'error': _reason(exc),
        }


def probe_node_rf(
    node: Node,
    ports: list[int],
    timeout: float = TIMEOUT,
) -> dict[str, Any]:
    """Все порты подписки одной ноды. Выключенная нода не опрашивается."""
    node_id = int(node.id or 0)
    host = node_host(node)
    view: dict[str, Any] = {
        'id': node_id,
        'host': host,
        'ok': False,
        'note': '',
        'ports': [],
    }
    if not node.enabled:
        return view
    wanted = clean_ports(ports)
    if not host:
        view['note'] = _note(view)
        return view
    if not wanted:
        view['note'] = _note(view)
        return view
    reference_ms = _reference_ms(host, reference_port(node, wanted), timeout)
    for port in wanted:
        view['ports'].append(_judge_port(host, port, timeout, reference_ms))
    view['ok'] = all(bool(row.get('ok')) for row in view['ports'])
    view['note'] = _note(view)
    return view


def probe_nodes_rf(
    nodes: list[Node],
    ports_by_node: dict[int, list[int]],
    timeout: float = TIMEOUT,
) -> dict[int, dict[str, Any]]:
    """Проверить включённые ноды параллельно. Ключ — id ноды."""
    pending = [node for node in nodes if node.id and node.enabled]
    if not pending:
        return {}
    views: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(pending))) as pool:
        futures = {
            pool.submit(
                probe_node_rf,
                node,
                ports_by_node.get(int(node.id or 0)) or [],
                timeout,
            ): int(node.id or 0)
            for node in pending
        }
        for future in as_completed(futures):
            node_id = futures[future]
            try:
                views[node_id] = future.result()
            except Exception as exc:  # noqa: BLE001
                views[node_id] = {
                    'id': node_id,
                    'host': '',
                    'ok': False,
                    'note': str(exc)[:120],
                    'ports': [],
                }
    return views


def store(node: Node, view: dict[str, Any]) -> None:
    """Запомнить результат в ноде, чтобы лампочка жила до следующей проверки."""
    node.rf_checked_at = utcnow()
    node.rf_ok = bool(view.get('ok'))
    node.rf_note = str(view.get('note') or '')[:_NOTE_LIMIT]


def _reference_ms(host: str, port: int, timeout: float) -> int | None:
    if port <= 0:
        return None
    try:
        row = probe_port(host, port, timeout)
    except Exception:
        return None
    if not row.get('ok'):
        return None
    return int(row.get('ms') or 0)


def _judge_port(
    host: str,
    port: int,
    timeout: float,
    reference_ms: int | None,
) -> dict[str, Any]:
    try:
        row = probe_port(host, port, timeout)
    except Exception as exc:  # noqa: BLE001
        return {'port': port, 'ok': False, 'ms': 0, 'error': str(exc)[:120]}
    if row.get('ok') and accepted_elsewhere(int(row.get('ms') or 0), reference_ms):
        row['ok'] = False
        row['error'] = f'принят не сервером (ориентир {reference_ms} мс)'
    return row


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _note(view: dict[str, Any]) -> str:
    ports = view.get('ports') or []
    if not view.get('host'):
        return 'не указан адрес сервера'
    if not ports:
        return 'нет портов в подписке'
    bits: list[str] = []
    for row in ports:
        if row.get('ok'):
            bits.append(f"{row['port']} есть ({row.get('ms')} мс)")
        else:
            bits.append(f"{row['port']} нет — {row.get('error') or 'не отвечает'}")
    return ' · '.join(bits)


def _reason(exc: OSError) -> str:
    code = getattr(exc, 'errno', None)
    if code == errno.ECONNREFUSED:
        return 'порт закрыт'
    if code in {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN}:
        return 'маршрут не найден'
    if code == errno.ECONNRESET:
        return 'соединение сброшено'
    if code in {errno.ETIMEDOUT, errno.EAGAIN}:
        return 'нет ответа'
    return str(exc)[:120] or 'не отвечает'
