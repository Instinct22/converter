from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

from app.models import Node
from app.util import cpu_percent
from app.xui import XuiClient, XuiError, as_obj, clean_version, versions_from_status


def _status_bits(obj: dict[str, Any]) -> dict[str, Any]:
    mem = obj.get('mem') if isinstance(obj.get('mem'), dict) else {}
    xray = obj.get('xray') if isinstance(obj.get('xray'), dict) else {}
    panel_version, xray_version = versions_from_status(obj)
    return {
        'cpu': cpu_percent(obj.get('cpu')),
        'mem_used': mem.get('current'),
        'mem_total': mem.get('total'),
        'uptime': obj.get('uptime'),
        'xray': xray.get('state') or '',
        'tcp': obj.get('tcpCount'),
        'udp': obj.get('udpCount'),
        'panel_version': panel_version,
        'xray_version': xray_version,
    }


def store_versions(node: Node, status: dict[str, Any]) -> bool:
    """Запомнить версии панели 3x-ui и ядра Xray, если панель их отдала.

    Старые панели (2.5.x) версию панели в этом ответе не отдают вовсе, поэтому
    найденное дописываем поверх, а не затираем пустым: колбэк вызывается на каждом
    опросе, и «версия пропала» чаще означает «панель старая», а не «сервер откатился».
    """
    panel = clean_version(status.get('panel_version'))
    core = clean_version(status.get('xray_version'))
    if not panel and not core:
        return False
    node.xui_version = panel or node.xui_version or ''
    node.xray_version = core or node.xray_version or ''
    node.version_checked_at = datetime.now(timezone.utc)
    return True


def client_rows_from_inbounds(remote: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in remote:
        settings = as_obj(raw.get('settings')) or {}
        clients = settings.get('clients') if isinstance(settings, dict) else []
        uuid_by_email: dict[str, str] = {}
        if isinstance(clients, list):
            for client in clients:
                if isinstance(client, dict) and client.get('email'):
                    uuid_by_email[str(client.get('email'))] = str(client.get('id') or '')
        for st in raw.get('clientStats') or []:
            if not isinstance(st, dict):
                continue
            email = str(st.get('email') or '')
            rows.append(
                {
                    'email': email,
                    'uuid': uuid_by_email.get(email) or '',
                    'up': int(st.get('up') or 0),
                    'down': int(st.get('down') or 0),
                    'total': int(st.get('total') or 0),
                }
            )
    return rows


def probe_node(node: Node) -> dict[str, Any]:
    out: dict[str, Any] = {
        'id': node.id,
        'online': False,
        'error': '',
        'status': {},
        'inbound_count': 0,
        'client_rows': [],
        'online_emails': [],
    }
    try:
        with XuiClient(node, timeout=5.0) as xui:
            try:
                out['status'] = _status_bits(xui.server_status())
            except XuiError:
                if xui.unreachable:
                    raise
                out['status'] = {}
            remote = xui.inbounds()
            out['inbound_count'] = len(remote)
            out['client_rows'] = client_rows_from_inbounds(remote)
            try:
                out['online_emails'] = xui.onlines()
                out['presence_valid'] = True
            except XuiError:
                if xui.unreachable:
                    raise
                out['online_emails'] = []
        out['online'] = True
    except Exception as exc:
        out['error'] = str(exc)
    return out


def probe_presence(node: Node) -> dict[str, Any]:
    """Кто в сети и сколько трафика потратил. Без статуса Xray и загрузки CPU."""
    out: dict[str, Any] = {
        'id': node.id,
        'online': False,
        'error': '',
        'online_emails': [],
        'client_rows': [],
    }
    try:
        with XuiClient(node, timeout=5.0) as xui:
            out['client_rows'] = client_rows_from_inbounds(xui.inbounds())
            out['online_emails'] = xui.onlines()
        out['online'] = True
    except Exception as exc:
        out['error'] = str(exc)
    return out


def probe_nodes_presence(nodes: list[Node]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    if not nodes:
        return result
    workers = min(8, len(nodes))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe_presence, node): node.id for node in nodes if node.id}
        for fut in as_completed(futs):
            node_id = futs[fut]
            try:
                result[node_id] = fut.result()
            except Exception as exc:
                result[node_id] = {
                    'id': node_id,
                    'online': False,
                    'error': str(exc),
                    'online_emails': [],
                    'client_rows': [],
                }
    return result


def probe_nodes(nodes: list[Node]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    if not nodes:
        return result
    workers = min(8, len(nodes))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe_node, node): node.id for node in nodes if node.id}
        for fut in as_completed(futs):
            node_id = futs[fut]
            try:
                result[node_id] = fut.result()
            except Exception as exc:
                result[node_id] = {
                    'id': node_id,
                    'online': False,
                    'error': str(exc),
                    'status': {},
                    'inbound_count': 0,
                    'client_rows': [],
                    'online_emails': [],
                }
    return result


def match_client_row(client_slug: str, client_uuid: str, row: dict[str, Any]) -> bool:
    email = str(row.get('email') or '')
    uuid = str(row.get('uuid') or '')
    if client_uuid and uuid and uuid == client_uuid:
        return True
    if email == client_slug or email.startswith(f'{client_slug}-'):
        return True
    return False


def client_is_online(client_slug: str, emails: list[str]) -> bool:
    slug = (client_slug or '').strip().lower()
    if not slug:
        return False
    for raw in emails:
        email = str(raw or '').strip().lower()
        if email == slug or email.startswith(f'{slug}-'):
            return True
    return False


def aggregate_client_usage(client, nodes: list[Node], probes: dict[int, dict[str, Any]]) -> dict[str, Any]:
    up = down = 0
    online_now = 0
    on_nodes = 0
    for node in nodes:
        probe = probes.get(node.id or 0) or {}
        rows = [
            row
            for row in probe.get('client_rows') or []
            if match_client_row(client.slug, client.uuid, row)
        ]
        if rows:
            on_nodes += 1
        for row in rows:
            up += int(row.get('up') or 0)
            down += int(row.get('down') or 0)
        if client_is_online(client.slug, probe.get('online_emails') or []):
            online_now += 1
    return {
        'up': up,
        'down': down,
        'used': up + down,
        'online_nodes': online_now,
        'seen_on_nodes': on_nodes,
    }
