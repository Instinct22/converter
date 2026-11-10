"""Виден ли сервер клиентам из России.

Мастер стоит в РФ, поэтому TCP-соединение к портам входов прямо отсюда —
это и есть ответ на вопрос «доходит ли нода до российских клиентов».
Панель 3x-ui при этом остаётся зелёной: у неё свой порт, и он отвечает.

Порты входов (443 и остальные) SSH не трогают, а мастер внесён в ignoreip
fail2ban, так что прообы бан не наживают. Проверка только TCP: DPI, который
обрывает соединение на ClientHello по SNI, так не увидеть.

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


def probe_nodes_rf(
    nodes: list[Node],
    ports_by_node: dict[int, list[int]],
    timeout: float = TIMEOUT,
) -> dict[int, dict[str, Any]]:
    """Проверить все порты всех нод параллельно. Ключ — id ноды."""
    views: dict[int, dict[str, Any]] = {}
    tasks: list[tuple[int, str, int]] = []
    for node in nodes:
        node_id = int(node.id or 0)
        if not node_id:
            continue
        host = node_host(node)
        views[node_id] = {'id': node_id, 'host': host, 'ok': False, 'note': '', 'ports': []}
        for port in clean_ports(ports_by_node.get(node_id) or []):
            tasks.append((node_id, host, port))
    if tasks:
        with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
            futures = {
                pool.submit(probe_port, host, port, timeout): (node_id, port)
                for node_id, host, port in tasks
            }
            for future in as_completed(futures):
                node_id, port = futures[future]
                try:
                    row = future.result()
                except Exception as exc:  # noqa: BLE001
                    row = {'port': port, 'ok': False, 'ms': 0, 'error': str(exc)[:120]}
                views[node_id]['ports'].append(row)
    for view in views.values():
        view['ports'].sort(key=lambda row: int(row.get('port') or 0))
        view['ok'] = any(bool(row.get('ok')) for row in view['ports'])
        view['note'] = _note(view)
    return views


def store(node: Node, view: dict[str, Any]) -> None:
    """Запомнить результат в ноде, чтобы лампочка жила до следующей проверки."""
    node.rf_checked_at = utcnow()
    node.rf_ok = bool(view.get('ok'))
    node.rf_note = str(view.get('note') or '')[:_NOTE_LIMIT]


def sort_key(node: Node) -> int:
    if node.rf_checked_at is None:
        return -1
    return 1 if node.rf_ok else 0


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
