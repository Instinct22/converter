from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

import httpx
from sqlmodel import Session, select

from app.crypto_reality import generate_reality_keys, random_short_id
from app.firewall import sync_node_firewall
from app.models import (
    Client,
    ClientPlacement,
    InboundTemplate,
    Node,
    NodeInbound,
    NodeTemplateAssignment,
    utcnow,
)
from app.parse_inbound import parse_inbound
from app.util import flatten_logs, run_parallel
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
    return any(
        token in low
        for token in ('already exists', 'duplicate', 'unique constraint', 'already in use')
    )


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


def subscription_is_on(settings: dict) -> bool:
    value = settings.get('subEnable')
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


def with_subscription_off(settings: dict) -> dict | None:
    """Полный набор настроек панели с выключенной раздачей подписки."""
    if not subscription_is_on(settings):
        return None
    updated = dict(settings)
    updated['subEnable'] = False
    return updated


def disable_node_subscription(node: Node) -> str:
    """Выключить HTTP-подписку 3x-ui. Клиентский YAML собирает Master из своей базы."""
    with XuiClient(node) as xui:
        current = xui.panel_settings()
        updated = with_subscription_off(current)
        if updated is None:
            return f'{node.name}: подписка 3x-ui уже выключена'
        xui.update_settings(updated)
    return f'{node.name}: подписка 3x-ui выключена'


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


def _clash_sub_probe_url(node: Node, segment: str, sub_token: str) -> str:
    scheme = (node.sub_scheme or 'https').strip().rstrip(':/') or 'https'
    host = (node.public_host or '').strip()
    port = int(node.sub_port or 2096)
    seg = (segment or '').strip().strip('/')
    return f'{scheme}://{host}:{port}/{seg}/{sub_token}'


def _is_clash_yaml_response(response: httpx.Response) -> bool:
    if response.status_code != 200:
        return False
    ctype = (response.headers.get('content-type') or '').lower()
    if 'yaml' in ctype:
        return True
    text = response.text.lstrip()
    return text.startswith('proxies:') or text.startswith('proxy-groups:')


def resolve_clash_sub_path(node: Node, sub_token: str) -> str:
    """Pick a path segment that returns Mihomo/Clash YAML for sub_token.

    3x-ui may expose a broken subClashPath; subPath often serves base64, not YAML.
    """
    candidates: list[str] = []
    for item in (node.sub_clash_path, node.sub_path, 'clash'):
        seg = (item or '').strip().strip('/')
        if seg and seg not in candidates:
            candidates.append(seg)
    if not (node.public_host or '').strip() or not sub_token:
        return (node.sub_clash_path or '').strip().strip('/')
    headers = {'User-Agent': 'clash.meta/1.19.0'}
    for seg in candidates:
        url = _clash_sub_probe_url(node, seg, sub_token)
        try:
            with httpx.Client(verify=False, timeout=httpx.Timeout(3.0, read=6.0)) as client:
                response = client.get(url, headers=headers)
            if _is_clash_yaml_response(response):
                return seg
        except httpx.HTTPError:
            continue
    return ''


def refresh_clash_sub_path(session: Session, node: Node) -> None:
    row = session.exec(select(Client.sub_token).where(Client.enable.is_(True)).limit(1)).first()
    if not row:
        return
    segment = resolve_clash_sub_path(node, row)
    if segment:
        node.sub_clash_path = segment
        if (node.last_error or '').startswith('Clash YAML'):
            node.last_error = ''
    else:
        node.sub_clash_path = ''
        node.last_error = (
            'Clash YAML подписка недоступна: в 3x-ui включите Mihomo/Clash sub '
            'и проверьте subClashPath (subPath отдаёт base64, не YAML).'
        )


def node_template_ids(session: Session, node_id: int) -> list[int]:
    rows = session.exec(
        select(NodeTemplateAssignment.template_id).where(
            NodeTemplateAssignment.node_id == node_id
        )
    ).all()
    return [int(item) for item in rows]


def unprovision_template(session: Session, node: Node, template: InboundTemplate) -> list[str]:
    """Снять с ноды inbound этого шаблона, если порт больше никому не нужен."""
    logs: list[str] = []
    assigned = {
        row.id
        for row in templates_for_node(session, node)
        if row.id is not None and row.id != template.id
    }
    if any(row.port == template.port and row.id in assigned for row in templates_for_node(session, node)):
        logs.append(f'{template.name}: порт {template.port} оставлен, его держит другой вход')
        return logs
    rows = session.exec(
        select(NodeInbound).where(
            NodeInbound.node_id == node.id,
            NodeInbound.port == template.port,
        )
    ).all()
    if not rows:
        logs.append(f'{template.name}: на {node.name} порта {template.port} не было')
        return logs
    with XuiClient(node, timeout=20.0) as xui:
        for row in rows:
            xui.del_inbound(row.xui_inbound_id)
            for place in session.exec(
                select(ClientPlacement).where(ClientPlacement.inbound_id == row.id)
            ).all():
                session.delete(place)
            session.delete(row)
            logs.append(f'{node.name}: вход {template.name} ({template.port}) удалён')
    session.commit()
    return logs


def port_clash_logs(session: Session, template_ids: list[int]) -> list[str]:
    """Два шаблона на одном порту панель не примет. Не трогаем ноду и говорим, кто столкнулся."""
    by_port: dict[int, list[str]] = {}
    seen: set[int] = set()
    for tid in template_ids:
        if tid in seen:
            continue
        seen.add(tid)
        row = session.get(InboundTemplate, tid)
        if row is None or not row.enabled:
            continue
        by_port.setdefault(row.port, []).append(row.name)
    logs: list[str] = []
    for port, names in sorted(by_port.items()):
        if len(names) < 2:
            continue
        joined = ' и '.join(f'«{name}»' for name in names)
        logs.append(f'порт {port} не навесился: его делят входы {joined}. На сервере может быть только один')
    return logs


def panel_not_ready(node: Node) -> str:
    if (getattr(node, 'install_state', '') or '') == 'installing':
        return f'{node.name}: панель ещё ставится'
    if not (node.panel_url or '').strip() or not (node.api_token or '').strip():
        return f'{node.name}: панель ещё не подключена'
    return ''


def apply_node_templates(session: Session, node: Node, template_ids: list[int]) -> list[str]:
    """Галочка стоит — inbound создан на ноде. Галочку сняли — inbound удалён."""
    if waiting := panel_not_ready(node):
        return [waiting]
    clash = port_clash_logs(session, template_ids)
    if clash:
        return clash
    logs: list[str] = []
    wanted: list[int] = []
    seen: set[int] = set()
    for tid in template_ids:
        if tid in seen:
            continue
        seen.add(tid)
        wanted.append(tid)
    old = set(node_template_ids(session, node.id or 0))
    new = set(wanted)
    removed_ok: set[int] = set()
    for tid in sorted(old - new):
        template = session.get(InboundTemplate, tid)
        if template is None:
            removed_ok.add(tid)
            continue
        try:
            logs.extend(unprovision_template(session, node, template))
            removed_ok.add(tid)
        except XuiError as exc:
            logs.append(f'{template.name}: не удалён с {node.name}: {exc}')
    added = [tid for tid in wanted if tid not in old]
    added_ok: set[int] = set()
    if added:
        templates = [
            row
            for tid in added
            if (row := session.get(InboundTemplate, tid)) is not None and row.enabled
        ]
        missing = set(added) - {row.id for row in templates if row.id is not None}
        for tid in missing:
            logs.append(f'шаблон {tid} не найден или выключен')
        if templates:
            created = provision_templates(session, node, templates)
            logs.extend(created)
            for template in templates:
                if template.id is None:
                    continue
                marker = f'inbound {template.name}:{template.port}'
                if any(marker in line and ('обновлён' in line or 'создан' in line) for line in created):
                    added_ok.add(template.id)
                    logs.append(f'{node.name}: вход {template.name} ({template.port}) навешан')
                else:
                    logs.append(f'{node.name}: вход {template.name} ({template.port}) не навесился')
            if added_ok:
                clients = session.exec(select(Client)).all()
                for client in clients:
                    if client_wanted_on_panel(client):
                        logs.extend(provision_client(session, client, nodes=[node]))
    final = [tid for tid in wanted if tid in old or tid in added_ok]
    for tid in sorted(old - removed_ok):
        if tid not in final:
            final.append(tid)
    set_node_template_ids(session, node.id or 0, final)
    chosen = [
        row
        for tid in final
        if (row := session.get(InboundTemplate, tid)) is not None
    ]
    logs.extend(sync_template_fields(session, node, chosen))
    logs.extend(sync_node_firewall(node, {row.port for row in chosen}, session))
    if not logs:
        logs.append('Список входов не изменился')
    return logs


def reconcile_node_templates(session: Session, node: Node, template_ids: list[int]) -> list[str]:
    """Сверить панель с отмеченными шаблонами.

    Порт уже есть — не трогаем (ключи Reality остаются). Порта нет — создаём.
    Порт без отмеченного шаблона — удаляем.
    """
    if waiting := panel_not_ready(node):
        return [waiting]
    clash = port_clash_logs(session, template_ids)
    if clash:
        return clash
    logs: list[str] = []
    wanted: list[InboundTemplate] = []
    seen: set[int] = set()
    for tid in template_ids:
        if tid in seen:
            continue
        seen.add(tid)
        row = session.get(InboundTemplate, tid)
        if row is None or not row.enabled:
            logs.append(f'шаблон {tid} не найден или выключен')
            continue
        wanted.append(row)
    by_port = {row.port: row for row in wanted}
    created: list[InboundTemplate] = []
    with XuiClient(node, timeout=20.0) as xui:
        remote = xui.inbounds()
        present: dict[int, list[int]] = {}
        for raw in remote:
            try:
                port = int(raw.get('port'))
                inbound_id = int(raw.get('id'))
            except (TypeError, ValueError):
                continue
            present.setdefault(port, []).append(inbound_id)
        for port, inbound_ids in present.items():
            if port in by_port:
                logs.append(f'{node.name}: порт {port} уже есть')
                continue
            for inbound_id in inbound_ids:
                try:
                    xui.del_inbound(inbound_id)
                    logs.append(f'{node.name}: лишний порт {port} удалён')
                except XuiError as exc:
                    logs.append(f'{node.name}: порт {port} не удалён: {exc}')
        for port, template in by_port.items():
            if port in present:
                continue
            try:
                xui.add_inbound(build_inbound_spec(template))
                created.append(template)
                logs.append(f'{node.name}: вход {template.name} ({port}) создан')
            except XuiError as exc:
                logs.append(f'{node.name}: вход {template.name} ({port}) не создан: {exc}')
    try:
        rows = sync_node(session, node, apply_templates=False)
    except XuiError as exc:
        logs.append(f'{node.name}: sync: {exc}')
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        rows = []
    created_ports = {row.port for row in created}
    for row in rows:
        template = by_port.get(row.port) if row.port in created_ports else None
        if template is not None:
            apply_subscription_from_template(row, template)
            session.add(row)
    if created_ports:
        session.commit()
    set_node_template_ids(session, node.id or 0, [row.id for row in wanted if row.id is not None])
    if created:
        for client in session.exec(select(Client)).all():
            if client_wanted_on_panel(client):
                logs.extend(provision_client(session, client, nodes=[node]))
    logs.extend(sync_template_fields(session, node, wanted))
    logs.extend(sync_node_firewall(node, {row.port for row in wanted}, session))
    return logs


def reconcile_all_nodes(session: Session) -> list[str]:
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    jobs = [
        (node.id, node.name, node_template_ids(session, node.id))
        for node in nodes
        if node.id is not None
    ]

    def run(job: tuple[int, str, list[int]]) -> list[str]:
        node_id, name, ids = job
        if not ids:
            return [f'{name}: шаблоны не выбраны']
        from app.database import engine

        with Session(engine) as local:
            node = local.get(Node, node_id)
            if node is None:
                return [f'{name}: сервер не найден']
            try:
                return reconcile_node_templates(local, node, ids)
            except XuiError as exc:
                node.last_error = str(exc)[:500]
                local.add(node)
                local.commit()
                return [f'{name}: {exc}']

    return flatten_logs(run_parallel(jobs, run))


def set_node_template_ids(session: Session, node_id: int, template_ids: list[int]) -> None:
    for row in session.exec(
        select(NodeTemplateAssignment).where(NodeTemplateAssignment.node_id == node_id)
    ).all():
        session.delete(row)
    seen: set[int] = set()
    for tid in template_ids:
        if tid in seen:
            continue
        seen.add(tid)
        session.add(NodeTemplateAssignment(node_id=node_id, template_id=tid))
    session.commit()


def templates_for_node(session: Session, node: Node | int) -> list[InboundTemplate]:
    node_id = node.id if isinstance(node, Node) else int(node)
    ids = node_template_ids(session, node_id)
    if ids:
        rows = session.exec(
            select(InboundTemplate).where(
                InboundTemplate.id.in_(ids),
                InboundTemplate.enabled == True,  # noqa: E712
            )
        ).all()
        order = {tid: idx for idx, tid in enumerate(ids)}
        return sorted(rows, key=lambda row: (order.get(row.id or 0, 999), row.port))
    return session.exec(
        select(InboundTemplate).where(InboundTemplate.enabled == True)  # noqa: E712
    ).all()


def templates_by_port_for_node(session: Session, node: Node) -> dict[int, InboundTemplate]:
    by_port: dict[int, InboundTemplate] = {}
    for template in templates_for_node(session, node):
        by_port[template.port] = template
    return by_port


def apply_subscription_from_template(
    row: NodeInbound,
    template: InboundTemplate | None,
) -> None:
    if template is None:
        return
    row.server_names = template.server_names
    row.extra_snis = template.extra_snis
    row.provider_label = template.provider_label
    row.use_in_sub = template.use_in_sub
    row.use_global_sni = template.use_global_sni
    row.snis_locked = True


def sync_template_fields(
    session: Session,
    node: Node,
    templates: Iterable[InboundTemplate],
) -> list[str]:
    """Переписать SNI входа с шаблона в Master и на панель.

    Ключи Reality не трогаем. Подписка читает имена с записи входа в Master,
    а не из карточки шаблона. Если синхронизация прошла раньше, чем шаблон
    привязали к ноде, в конфиге остаются старые имена.
    """
    by_port: dict[int, InboundTemplate] = {}
    for template in templates:
        if template.enabled:
            by_port[template.port] = template
    if not by_port or node.id is None:
        return []
    logs: list[str] = []
    rows = session.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).all()
    for row in rows:
        template = by_port.get(row.port)
        if template is None:
            continue
        names = split_csv(template.server_names)
        same = split_csv(row.server_names) == names and split_csv(row.extra_snis) == split_csv(template.extra_snis)
        row.server_names = template.server_names
        row.extra_snis = template.extra_snis
        row.snis_locked = True
        label = (template.provider_label or '').strip()
        if not label and names:
            host = names[0].split(':')[0].strip().lower()
            parts = [part for part in host.split('.') if part]
            label = parts[1] if len(parts) >= 2 and parts[0] == 'www' else (parts[0] if parts else '')
        if label:
            row.provider_label = label
        session.add(row)
        if not same:
            try:
                push_server_names(node, row, names)
                logs.append(f'{node.name}: SNI «{template.name}» ({row.port}) в конфиге, {len(names)} имён')
            except XuiError as exc:
                logs.append(f'{node.name}: SNI «{template.name}» ({row.port}) не записались на панель: {exc}')
        remark = (template.name or '').strip()
        if remark and remark != (row.remark or ''):
            try:
                push_inbound_remark(node, row, remark)
                row.remark = remark
                session.add(row)
                logs.append(f'{node.name}: имя входа ({row.port}) теперь «{remark}»')
            except XuiError as exc:
                logs.append(f'{node.name}: имя входа ({row.port}) не записалось на панель: {exc}')
    session.commit()
    return logs


def ensure_default_node_templates(session: Session) -> None:
    templates = session.exec(
        select(InboundTemplate).where(InboundTemplate.enabled == True)  # noqa: E712
    ).all()
    if not templates:
        return
    template_ids = [t.id for t in templates if t.id is not None]
    nodes = session.exec(select(Node)).all()
    for node in nodes:
        if node.id is None:
            continue
        if node_template_ids(session, node.id):
            continue
        set_node_template_ids(session, node.id, template_ids)


def sync_node(session: Session, node: Node, *, apply_templates: bool = True) -> list[NodeInbound]:
    with XuiClient(node) as xui:
        try:
            current = xui.panel_settings()
            apply_sub_settings(node, current)
            updated = with_subscription_off(current)
            if updated is not None:
                xui.update_settings(updated)
        except XuiError:
            pass
        remote = xui.inbounds()
    seen: set[int] = set()
    template_by_port = templates_by_port_for_node(session, node)
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
        tpl = template_by_port.get(parsed['port']) if apply_templates else None
        if tpl is not None:
            apply_subscription_from_template(row, tpl)
        elif not row.snis_locked:
            row.server_names = parsed['server_names']
        elif not (row.server_names or '').strip():
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


def build_inbound_spec(template: InboundTemplate, seed: dict | None = None) -> dict:
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
        'settings': json.dumps(
            {
                'clients': [seed] if seed else [],
                'decryption': 'none',
                'fallbacks': [],
            }
        ),
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


def _keep_remote_clients(existing: dict, spec: dict) -> dict:
    payload = dict(spec)
    payload['id'] = existing.get('id')
    settings = existing.get('settings')
    if isinstance(settings, dict):
        payload['settings'] = json.dumps(settings)
    elif settings:
        payload['settings'] = settings
    return payload


def provision_templates(session: Session, node: Node, templates: Iterable[InboundTemplate]) -> list[str]:
    logs: list[str] = []
    ordered = sorted(list(templates), key=lambda row: (row.port, row.id or 0))
    with XuiClient(node, timeout=20.0) as xui:
        remote = xui.inbounds()
        by_port: dict[int, dict] = {}
        for raw in remote:
            try:
                by_port[int(raw.get('port'))] = raw
            except (TypeError, ValueError):
                continue
        for template in ordered:
            spec = build_inbound_spec(template)
            existing = by_port.get(template.port)
            try:
                if existing:
                    inbound_id = int(existing.get('id'))
                    xui.update_inbound(inbound_id, _keep_remote_clients(existing, spec))
                    logs.append(f'inbound {template.name}:{template.port} обновлён')
                else:
                    xui.add_inbound(spec)
                    logs.append(f'inbound {template.name}:{template.port} создан')
            except XuiError as exc:
                logs.append(f'inbound {template.name}:{template.port}: {exc}')
    try:
        sync_node(session, node)
    except XuiError as exc:
        logs.append(f'sync: {exc}')
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        return logs
    session.commit()
    logs.extend(sync_template_fields(session, node, ordered))
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


def _provision_client_node(session: Session, client: Client, node: Node) -> list[str]:
    logs: list[str] = []
    inbounds = session.exec(
        select(NodeInbound).where(NodeInbound.node_id == node.id)
    ).all()
    if not inbounds:
        return [f'{node.name}: нет inbound для подписки — сначала sync/provision']
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
        node.last_error = str(exc)[:500]
        session.add(node)
    return logs


def provision_client(
    session: Session,
    client: Client,
    nodes: list[Node] | None = None,
) -> list[str]:
    if nodes is None:
        nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
    if not client_wanted_on_panel(client):
        logs = delete_client_remote(session, client, nodes=nodes)
        if not logs:
            logs.append(f'{client.name}: выключен или истёк — с серверов убран')
        return logs
    node_ids = [node.id for node in nodes if node.id is not None]
    if len(node_ids) <= 1:
        logs: list[str] = []
        for node in nodes:
            if node.id is None:
                continue
            logs.extend(_provision_client_node(session, client, node))
        session.commit()
        return logs

    client_id = client.id

    def run(node_id: int) -> list[str]:
        from app.database import engine

        with Session(engine) as local:
            local_client = local.get(Client, client_id)
            local_node = local.get(Node, node_id)
            if local_client is None or local_node is None:
                return []
            lines = _provision_client_node(local, local_client, local_node)
            local.commit()
            return lines

    return flatten_logs(run_parallel(node_ids, run))


def delete_client_remote(
    session: Session,
    client: Client,
    nodes: list[Node] | None = None,
) -> list[str]:
    logs: list[str] = []
    if nodes is None:
        nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
    target_ids = {node.id for node in nodes if node.id}
    node_ids = [node.id for node in nodes if node.id is not None]
    client_id = client.id

    def drop_on(local: Session, local_client: Client, node: Node) -> list[str]:
        lines: list[str] = []
        inbounds = local.exec(
            select(NodeInbound).where(NodeInbound.node_id == node.id)
        ).all()
        emails = {local_client.slug}
        inbound_id = inbounds[0].xui_inbound_id if inbounds else 0
        for inbound in inbounds:
            emails.add(client_email(local_client, inbound))
        try:
            with XuiClient(node) as xui:
                for email in emails:
                    try:
                        xui.del_client(inbound_id, local_client.uuid, email=email)
                        lines.append(f'{node.name}: {email} убран')
                    except XuiError as exc:
                        lines.append(f'{node.name}: {email} {exc}')
        except XuiError as exc:
            lines.append(f'{node.name}: {exc}')
        return lines

    if len(node_ids) <= 1:
        for node in nodes:
            if node.id is None:
                continue
            logs.extend(drop_on(session, client, node))
    else:
        def run(node_id: int) -> list[str]:
            from app.database import engine

            with Session(engine) as local:
                local_client = local.get(Client, client_id)
                node = local.get(Node, node_id)
                if local_client is None or node is None:
                    return []
                return drop_on(local, local_client, node)

        logs.extend(flatten_logs(run_parallel(node_ids, run)))
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
    def sweep(node_id: int) -> list[str]:
        from app.database import engine

        lines: list[str] = []
        with Session(engine) as local:
            node = local.get(Node, node_id)
            roster = local.exec(select(Client)).all()
            if node is None:
                return lines
            try:
                with XuiClient(node) as xui:
                    for row in xui.list_clients():
                        ident = panel_client_ident(row)
                        if not ident['email'] or is_panel_seed(ident):
                            continue
                        master = match_master_client(ident, roster)
                        if master is not None and client_wanted_on_panel(master):
                            continue
                        reason = 'нет в Master' if master is None else 'выключен или истёк'
                        try:
                            xui.del_client(0, ident['id'], email=ident['email'])
                            lines.append(f'{node.name}: {ident["email"]} убран ({reason})')
                        except XuiError as exc:
                            lines.append(f'{node.name}: {ident["email"]} {exc}')
            except XuiError as exc:
                lines.append(f'{node.name}: {exc}')
                node.last_error = str(exc)[:500]
                local.add(node)
                local.commit()
        return lines

    node_ids = [node.id for node in nodes if node.id is not None]
    logs.extend(flatten_logs(run_parallel(node_ids, sweep)))
    for client in clients:
        if client_wanted_on_panel(client):
            logs.extend(provision_client(session, client, nodes=nodes))
        else:
            logs.extend(delete_client_remote(session, client, nodes=nodes))
    if not logs:
        logs.append('Серверы совпадают с Master')
    return logs


def push_inbound_remark(node: Node, inbound: NodeInbound, remark: str) -> None:
    """Меняет только подпись входа в 3x-ui. Ключи и клиенты не трогает."""
    with XuiClient(node) as xui:
        obj = xui.get_inbound(inbound.xui_inbound_id)
        if str(obj.get('remark') or '') == remark:
            return
        obj['remark'] = remark
        settings = as_obj(obj.get('settings'))
        if isinstance(settings, dict):
            obj['settings'] = json.dumps(settings)
        stream = as_obj(obj.get('streamSettings'))
        if isinstance(stream, dict):
            obj['streamSettings'] = json.dumps(stream)
        sniffing = as_obj(obj.get('sniffing'))
        if isinstance(sniffing, dict):
            obj['sniffing'] = json.dumps(sniffing)
        xui.update_inbound(inbound.xui_inbound_id, obj)


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
