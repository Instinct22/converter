from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Iterable

from sqlmodel import Session, select

from app.crypto_reality import generate_reality_keys, random_short_id
from app.models import Client, ClientPlacement, InboundTemplate, Node, NodeInbound, utcnow
from app.parse_inbound import parse_inbound
from app.xui import XuiClient, XuiError, as_obj, email_from_client_row


def split_csv(text: str) -> list[str]:
    return [part.strip() for part in (text or '').split(',') if part.strip()]


def client_email(client: Client, inbound: NodeInbound | None = None) -> str:
    if inbound is None:
        return client.slug
    return f'{client.slug}-{inbound.port}-{inbound.xui_inbound_id}'


def client_payload(client: Client, inbound: NodeInbound | None = None) -> dict:
    expire_ms = 0
    if client.expire_at:
        expire_ms = int(client.expire_at.timestamp() * 1000)
    return {
        'id': client.uuid,
        'email': client.slug,
        'flow': (inbound.flow if inbound else '') or '',
        'enable': client.enable,
        'limitIp': client.limit_ip or 0,
        'totalGB': client.traffic_limit_bytes or 0,
        'expiryTime': expire_ms,
        'subId': client.sub_token,
        'tgId': 0,
        'reset': 0,
        'comment': client.name,
    }


def _already_on_panel(text: str) -> bool:
    low = text.lower()
    return any(token in low for token in ('already exists', 'duplicate', 'unique constraint'))


def client_wanted_on_panel(client: Client) -> bool:
    if not client.enable:
        return False
    if not client.expire_at:
        return True
    expire = client.expire_at
    if expire.tzinfo is None:
        expire = expire.replace(tzinfo=timezone.utc)
    return expire > datetime.now(timezone.utc)


def panel_client_ident(row: dict) -> dict[str, str]:
    inner = row.get('client') if isinstance(row.get('client'), dict) else row
    if not isinstance(inner, dict):
        return {'email': '', 'id': '', 'subId': ''}
    return {
        'email': str(inner.get('email') or ''),
        'id': str(inner.get('id') or inner.get('uuid') or ''),
        'subId': str(inner.get('subId') or inner.get('sub_id') or ''),
    }


def is_panel_seed(ident: dict[str, str]) -> bool:
    email = ident.get('email') or ''
    sub = ident.get('subId') or ''
    return email.startswith('master-seed') or sub == 'masterseed'


def match_master_client(ident: dict[str, str], clients: list[Client]) -> Client | None:
    email = ident.get('email') or ''
    uuid = ident.get('id') or ''
    sub = ident.get('subId') or ''
    for client in clients:
        if uuid and uuid == client.uuid:
            return client
        if sub and sub == client.sub_token:
            return client
        if email and email == client.slug:
            return client
        if email and email.startswith(f'{client.slug}-'):
            return client
    return None


def apply_sub_settings(node: Node, settings: dict) -> None:
    port = settings.get('subPort')
    try:
        node.sub_port = int(port or 2096)
    except (TypeError, ValueError):
        node.sub_port = 2096
    clash_path = str(settings.get('subClashPath') or '').strip().strip('/')
    raw_path = str(settings.get('subPath') or '').strip().strip('/')
    node.sub_clash_path = clash_path
    node.sub_path = raw_path
    cert = str(settings.get('subCertFile') or '').strip()
    node.sub_scheme = 'https' if cert else 'http'
    domain = str(settings.get('subDomain') or '').strip()
    if domain:
        node.public_host = domain.split('/')[0].split(':')[0]


def sync_node(session: Session, node: Node) -> list[NodeInbound]:
    with XuiClient(node) as xui:
        try:
            apply_sub_settings(node, xui.panel_settings())
        except XuiError:
            pass
        remote = xui.inbounds()
    seen: set[int] = set()
    existing = {
        row.xui_inbound_id: row
        for row in session.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).all()
    }
    result: list[NodeInbound] = []
    for raw in remote:
        parsed = parse_inbound(raw)
        xui_id = parsed['xui_inbound_id']
        seen.add(xui_id)
        row = existing.get(xui_id)
        if row is None:
            row = NodeInbound(node_id=node.id, xui_inbound_id=xui_id)
            session.add(row)
        row.remark = parsed['remark']
        row.port = parsed['port']
        row.protocol = parsed['protocol']
        row.network = parsed['network']
        row.public_key = parsed['public_key']
        row.short_id = parsed['short_id']
        row.fingerprint = parsed['fingerprint']
        row.dest = parsed['dest']
        row.server_names = parsed['server_names']
        row.grpc_service_name = parsed['grpc_service_name']
        row.xhttp_path = parsed['xhttp_path']
        row.flow = parsed['flow']
        result.append(row)
    for xui_id, row in existing.items():
        if xui_id not in seen:
            stale = session.exec(
                select(ClientPlacement).where(ClientPlacement.inbound_id == row.id)
            ).all()
            for item in stale:
                session.delete(item)
            session.delete(row)
    node.last_sync_at = utcnow()
    node.last_error = ''
    session.add(node)
    session.commit()
    for row in result:
        session.refresh(row)
    return result


def _template_val(template: InboundTemplate, name: str, default: object = '') -> object:
    return getattr(template, name, default)


def build_inbound_spec(template: InboundTemplate, seed: dict) -> dict:
    network = template.network or 'tcp'
    security = str(_template_val(template, 'security', 'reality') or 'none')
    protocol = str(_template_val(template, 'protocol', 'vless') or 'vless')
    listen = str(_template_val(template, 'listen', '') or '')
    stream: dict = {
        'network': network,
        'security': security if security in {'none', 'tls', 'reality'} else 'reality',
        'externalProxy': [],
    }
    if network == 'grpc':
        stream['grpcSettings'] = {
            'serviceName': template.grpc_service_name or 'grpc',
            'authority': str(_template_val(template, 'grpc_authority', '') or ''),
            'multiMode': bool(_template_val(template, 'grpc_multi_mode', False)),
        }
    elif network in {'xhttp', 'splithttp'}:
        stream['xhttpSettings'] = {
            'path': template.xhttp_path or '/',
            'host': str(_template_val(template, 'xhttp_host', '') or ''),
            'mode': str(_template_val(template, 'xhttp_mode', 'auto') or 'auto'),
            'headers': {},
        }
    elif network in {'ws', 'websocket'}:
        stream['wsSettings'] = {
            'path': str(_template_val(template, 'ws_path', '/') or '/'),
            'host': str(_template_val(template, 'ws_host', '') or ''),
            'headers': {},
        }
    elif network == 'httpupgrade':
        stream['httpupgradeSettings'] = {
            'path': str(_template_val(template, 'ws_path', '/') or '/'),
            'host': str(_template_val(template, 'ws_host', '') or ''),
            'headers': {},
        }
    else:
        stream['tcpSettings'] = {
            'acceptProxyProtocol': False,
            'header': {'type': 'none'},
        }

    if stream['security'] == 'reality':
        private_key, public_key = generate_reality_keys()
        names: list[str] = []
        for item in split_csv(template.server_names) + split_csv(template.extra_snis):
            if item and item not in names:
                names.append(item)
        dest = (template.dest or '').strip()
        if dest and ':' not in dest:
            dest = f'{dest}:443'
        short_ids = split_csv(str(_template_val(template, 'short_ids', '') or ''))
        if not short_ids:
            short_ids = [random_short_id()]
        stream['realitySettings'] = {
            'show': False,
            'xver': 0,
            'target': dest,
            'dest': dest,
            'serverNames': names,
            'privateKey': private_key,
            'minClientVer': '',
            'maxClientVer': '',
            'maxTimediff': 0,
            'shortIds': short_ids,
            'settings': {
                'publicKey': public_key,
                'fingerprint': template.fingerprint or 'chrome',
                'serverName': '',
                'spiderX': str(_template_val(template, 'spider_x', '/') or '/'),
            },
        }
    elif stream['security'] == 'tls':
        stream['tlsSettings'] = {
            'serverName': str(_template_val(template, 'tls_server_name', '') or ''),
            'minVersion': '1.2',
            'maxVersion': '1.3',
            'cipherSuites': '',
            'rejectUnknownSni': bool(_template_val(template, 'reject_unknown_sni', False)),
            'alpn': split_csv(str(_template_val(template, 'tls_alpn', 'h2,http/1.1') or '')) or ['h2', 'http/1.1'],
            'certificates': [
                {
                    'certificateFile': str(_template_val(template, 'tls_cert_file', '') or ''),
                    'keyFile': str(_template_val(template, 'tls_key_file', '') or ''),
                    'oneTimeLoading': False,
                }
            ],
            'settings': {
                'allowInsecure': False,
                'fingerprint': template.fingerprint or 'chrome',
            },
        }

    sniff_on = bool(_template_val(template, 'sniffing', False))
    return {
        'up': 0,
        'down': 0,
        'total': 0,
        'remark': template.name,
        'enable': True,
        'expiryTime': 0,
        'listen': listen,
        'port': template.port,
        'protocol': protocol,
        'settings': json.dumps({'clients': [seed], 'decryption': 'none', 'fallbacks': []}),
        'streamSettings': json.dumps(stream),
        'sniffing': json.dumps(
            {
                'enabled': sniff_on,
                'destOverride': ['http', 'tls', 'quic', 'fakedns'],
                'metadataOnly': False,
                'routeOnly': False,
            }
        ),
    }


def provision_templates(session: Session, node: Node, templates: Iterable[InboundTemplate]) -> list[str]:
    logs: list[str] = []
    with XuiClient(node) as xui:
        for template in templates:
            seed = {
                'id': str(uuid.uuid4()),
                'email': f'master-seed-{template.port}-{uuid.uuid4().hex[:6]}',
                'flow': template.flow or '',
                'enable': False,
                'limitIp': 0,
                'totalGB': 0,
                'expiryTime': 0,
                'subId': 'masterseed',
                'tgId': 0,
                'comment': 'xui-master seed',
            }
            spec = build_inbound_spec(template, seed)
            try:
                xui.add_inbound(spec)
                logs.append(f'inbound {template.name}:{template.port} создан')
            except XuiError as exc:
                logs.append(f'inbound {template.name}:{template.port}: {exc}')
    try:
        inbounds = sync_node(session, node)
    except XuiError as exc:
        logs.append(f'sync: {exc}')
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        return logs
    session.commit()
    clients = session.exec(select(Client).where(Client.enable.is_(True))).all()
    for client in clients:
        logs.extend(provision_client(session, client, nodes=[node]))
    return logs


def _record_placement(
    session: Session,
    client: Client,
    node: Node,
    inbound: NodeInbound,
    ok: bool,
    message: str,
) -> None:
    row = session.exec(
        select(ClientPlacement).where(
            ClientPlacement.client_id == client.id,
            ClientPlacement.inbound_id == inbound.id,
        )
    ).first()
    if row is None:
        row = ClientPlacement(
            client_id=client.id or 0,
            node_id=node.id or 0,
            inbound_id=inbound.id or 0,
        )
        session.add(row)
    row.ok = ok
    row.message = message[:500]
    row.updated_at = utcnow()
    session.add(row)


def provision_client(
    session: Session,
    client: Client,
    nodes: list[Node] | None = None,
) -> list[str]:
    logs: list[str] = []
    if nodes is None:
        nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
    if not client_wanted_on_panel(client):
        logs.extend(delete_client_remote(session, client, nodes=nodes))
        if not logs:
            logs.append(f'{client.name}: выключен или истёк — с серверов убран')
        return logs
    for node in nodes:
        inbounds = session.exec(
            select(NodeInbound).where(NodeInbound.node_id == node.id)
        ).all()
        if not inbounds:
            logs.append(f'{node.name}: нет inbound для подписки — сначала sync/provision')
            continue
        try:
            with XuiClient(node) as xui:
                payload = client_payload(client, inbounds[0])
                inbound_ids = [item.xui_inbound_id for item in inbounds]
                try:
                    existing = xui.clients_by_sub(client.sub_token)
                    if existing:
                        found_email = email_from_client_row(existing[0]) or client.slug
                        payload['email'] = found_email
                        xui.update_client(found_email, payload)
                        xui.attach_client(found_email, inbound_ids)
                        status = 'updated'
                    else:
                        xui.add_client(inbound_ids, payload)
                        status = 'ok'
                    for inbound in inbounds:
                        _record_placement(session, client, node, inbound, True, status)
                        logs.append(f'{node.name}:{inbound.port} add ok')
                except XuiError as exc:
                    text = str(exc)
                    if _already_on_panel(text):
                        try:
                            xui.update_client(payload['email'], payload)
                            xui.attach_client(payload['email'], inbound_ids)
                            for inbound in inbounds:
                                _record_placement(session, client, node, inbound, True, 'updated')
                                logs.append(f'{node.name}:{inbound.port} update ok')
                        except XuiError as exc2:
                            for inbound in inbounds:
                                _record_placement(session, client, node, inbound, False, str(exc2))
                                logs.append(f'{node.name}:{inbound.port} {exc2}')
                    else:
                        for inbound in inbounds:
                            _record_placement(session, client, node, inbound, False, text)
                            logs.append(f'{node.name}:{inbound.port} {exc}')
        except XuiError as exc:
            logs.append(f'{node.name}: {exc}')
            node.last_error = str(exc)
            session.add(node)
    session.commit()
    return logs


def delete_client_remote(
    session: Session,
    client: Client,
    nodes: list[Node] | None = None,
) -> list[str]:
    logs: list[str] = []
    if nodes is None:
        nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
    target_ids = {node.id for node in nodes if node.id}
    for node in nodes:
        inbounds = session.exec(
            select(NodeInbound).where(NodeInbound.node_id == node.id)
        ).all()
        emails = {client.slug}
        inbound_id = inbounds[0].xui_inbound_id if inbounds else 0
        for inbound in inbounds:
            emails.add(client_email(client, inbound))
        try:
            with XuiClient(node) as xui:
                for email in emails:
                    try:
                        xui.del_client(inbound_id, client.uuid, email=email)
                        logs.append(f'{node.name}: {email} убран')
                    except XuiError as exc:
                        logs.append(f'{node.name}: {email} {exc}')
        except XuiError as exc:
            logs.append(f'{node.name}: {exc}')
    placements = session.exec(
        select(ClientPlacement).where(ClientPlacement.client_id == client.id)
    ).all()
    for row in placements:
        if row.node_id in target_ids:
            session.delete(row)
    session.commit()
    return logs


def reconcile_clients(session: Session) -> list[str]:
    logs: list[str] = []
    nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
    clients = session.exec(select(Client)).all()
    if not nodes:
        return ['Нет включённых серверов']
    for node in nodes:
        try:
            with XuiClient(node) as xui:
                for row in xui.list_clients():
                    ident = panel_client_ident(row)
                    if not ident['email'] or is_panel_seed(ident):
                        continue
                    master = match_master_client(ident, clients)
                    if master is not None and client_wanted_on_panel(master):
                        continue
                    reason = 'нет в Master' if master is None else 'выключен или истёк'
                    try:
                        xui.del_client(0, ident['id'], email=ident['email'])
                        logs.append(f'{node.name}: {ident["email"]} убран ({reason})')
                    except XuiError as exc:
                        logs.append(f'{node.name}: {ident["email"]} {exc}')
        except XuiError as exc:
            logs.append(f'{node.name}: {exc}')
            node.last_error = str(exc)
            session.add(node)
    for client in clients:
        if client_wanted_on_panel(client):
            logs.extend(provision_client(session, client, nodes=nodes))
        else:
            logs.extend(delete_client_remote(session, client, nodes=nodes))
    if not logs:
        logs.append('Серверы совпадают с Master')
    return logs


def push_server_names(node: Node, inbound: NodeInbound, names: list[str]) -> None:
    with XuiClient(node) as xui:
        obj = xui.get_inbound(inbound.xui_inbound_id)
        stream = as_obj(obj.get('streamSettings')) or {}
        if not isinstance(stream, dict):
            stream = {}
        rs = stream.get('realitySettings') or {}
        if not isinstance(rs, dict):
            rs = {}
        rs['serverNames'] = names
        stream['realitySettings'] = rs
        obj['streamSettings'] = json.dumps(stream)
        settings = as_obj(obj.get('settings'))
        if isinstance(settings, dict):
            obj['settings'] = json.dumps(settings)
        sniffing = as_obj(obj.get('sniffing'))
        if isinstance(sniffing, dict):
            obj['sniffing'] = json.dumps(sniffing)
        xui.update_inbound(inbound.xui_inbound_id, obj)


def disable_expired(session: Session) -> int:
    now = datetime.now(timezone.utc)
    changed = 0
    clients = session.exec(select(Client).where(Client.enable.is_(True))).all()
    for client in clients:
        if client.expire_at and client.expire_at <= now:
            client.enable = False
            session.add(client)
            provision_client(session, client)
            changed += 1
    return changed
