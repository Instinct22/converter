from __future__ import annotations

from typing import Any

from app.crypto_reality import public_from_private
from app.xui import as_obj


def parse_inbound(raw: dict[str, Any]) -> dict[str, Any]:
    settings = as_obj(raw.get('settings')) or {}
    stream = as_obj(raw.get('streamSettings')) or {}
    rs = stream.get('realitySettings') or {}
    nested = rs.get('settings') or {}
    public_key = nested.get('publicKey') or ''
    if not public_key and rs.get('privateKey'):
        try:
            public_key = public_from_private(rs['privateKey'])
        except Exception:
            public_key = ''
    short_ids = rs.get('shortIds') or []
    short_id = ''
    for item in short_ids:
        if item:
            short_id = str(item)
            break
    grpc = stream.get('grpcSettings') or {}
    xhttp = stream.get('xhttpSettings') or stream.get('splithttpSettings') or {}
    names = rs.get('serverNames') or []
    dest = rs.get('target') or rs.get('dest') or ''
    clients = settings.get('clients') or []
    flow = ''
    if clients:
        flow = clients[0].get('flow') or ''
    return {
        'xui_inbound_id': int(raw.get('id') or 0),
        'remark': str(raw.get('remark') or ''),
        'port': int(raw.get('port') or 0),
        'protocol': str(raw.get('protocol') or 'vless'),
        'network': str(stream.get('network') or 'tcp'),
        'public_key': public_key,
        'short_id': short_id,
        'fingerprint': nested.get('fingerprint') or 'chrome',
        'dest': dest,
        'server_names': ','.join(str(n) for n in names if n),
        'grpc_service_name': grpc.get('serviceName') or '',
        'xhttp_path': xhttp.get('path') or '',
        'flow': flow,
        'enable': bool(raw.get('enable', True)),
    }
