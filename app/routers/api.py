from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from app.deps import SessionDep, require_admin
from app.mihomo import days_left, is_expired, node_clash_sub_base, render_profile
from app.models import Client, ConfigDoc, InboundTemplate, Node, NodeInbound
from app.overview import aggregate_client_usage, probe_nodes
from app.sub_link import client_sub_url
from app.provision import (
    apply_sub_settings,
    delete_client_remote,
    node_template_ids,
    provision_client,
    provision_templates,
    push_server_names,
    reconcile_clients,
    set_node_template_ids,
    split_csv,
    sync_node,
    templates_for_node,
)
from app.tls_sni import fetch_dest_sni, parse_dest
from app.util import expire_from_days, format_bytes, new_token, new_uuid, slugify
from app.flags import to_iso
from app.xui import XuiClient, XuiError, normalize_panel_url, public_host_from_url

router = APIRouter(prefix='/api', dependencies=[Depends(require_admin)])


class NodeIn(BaseModel):
    flag: str = ''
    name: str
    clash_name: str = ''
    panel_url: str
    api_token: str


class NodePatch(BaseModel):
    flag: str | None = None
    name: str | None = None
    clash_name: str | None = None
    panel_url: str | None = None
    api_token: str | None = None
    public_host: str | None = None
    enabled: bool | None = None
    sort_order: int | None = None
    sub_port: int | None = None
    sub_path: str | None = None
    sub_clash_path: str | None = None
    sub_scheme: str | None = None
    template_ids: list[int] | None = None


class InboundPatch(BaseModel):
    server_names: str | None = None
    display_prefix: str | None = None
    use_in_sub: bool | None = None
    extra_snis: str | None = None
    use_global_sni: bool | None = None
    snis_locked: bool | None = None
    provider_label: str | None = None
    push_panel: bool = True


class TemplateIn(BaseModel):
    name: str
    port: int
    protocol: str = 'vless'
    listen: str = ''
    network: str = 'grpc'
    security: str = 'reality'
    dest: str = 'www.cloudflare.com:443'
    server_names: str = 'www.cloudflare.com'
    grpc_service_name: str = 'grpc'
    grpc_authority: str = ''
    grpc_multi_mode: bool = False
    xhttp_path: str = '/'
    xhttp_host: str = ''
    xhttp_mode: str = 'auto'
    ws_path: str = '/'
    ws_host: str = ''
    fingerprint: str = 'chrome'
    flow: str = ''
    spider_x: str = '/'
    short_ids: str = ''
    sniffing: bool = False
    tls_cert_file: str = ''
    tls_key_file: str = ''
    tls_alpn: str = 'h2,http/1.1'
    tls_server_name: str = ''
    reject_unknown_sni: bool = False
    extra_snis: str = ''
    use_global_sni: bool = False
    enabled: bool = True
    use_in_sub: bool = True
    provider_label: str = ''


class ClientIn(BaseModel):
    name: str
    days: int = 30
    traffic_gb: int = 0
    limit_ip: int = 0
    note: str = ''


class ClientPatch(BaseModel):
    name: str | None = None
    enable: bool | None = None
    days: int | None = None
    add_days: int | None = None
    traffic_gb: int | None = None
    limit_ip: int | None = None
    note: str | None = None


class ConfigIn(BaseModel):
    yaml_text: str
    pool_group_names: str | None = None
    global_extra_snis: str | None = None


def _node_out(node: Node, session: Session | None = None) -> dict:
    out = {
        'id': node.id,
        'flag': node.flag,
        'name': node.name,
        'clash_name': node.clash_name,
        'clash_prefix': node.clash_prefix(),
        'panel_url': node.panel_url,
        'has_api_token': bool((node.api_token or '').strip()),
        'public_host': node.public_host,
        'enabled': node.enabled,
        'sort_order': node.sort_order,
        'last_sync_at': node.last_sync_at.isoformat() if node.last_sync_at else None,
        'last_error': node.last_error,
        'sub_port': node.sub_port,
        'sub_path': node.sub_path,
        'sub_clash_path': node.sub_clash_path,
        'sub_scheme': node.sub_scheme,
        'clash_sub_base': node_clash_sub_base(node),
    }
    if session is not None and node.id is not None:
        out['template_ids'] = node_template_ids(session, node.id)
    return out


@router.get('/nodes')
def list_nodes(session: SessionDep) -> list[dict]:
    rows = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    return [_node_out(n, session) for n in rows]


@router.post('/nodes')
def create_node(body: NodeIn, session: SessionDep) -> dict:
    token = body.api_token.strip()
    if not token:
        raise HTTPException(400, 'Нужен API Token')
    panel_url = normalize_panel_url(body.panel_url)
    node = Node(
        flag=to_iso(body.flag) or body.flag.strip(),
        name=body.name.strip(),
        clash_name=(body.clash_name or body.name).strip(),
        panel_url=panel_url,
        api_token=token,
        public_host=public_host_from_url(panel_url),
        enabled=True,
    )
    session.add(node)
    session.commit()
    session.refresh(node)
    logs: list[str] = []
    try:
        with XuiClient(node) as xui:
            xui.login()
        logs.append('API ok')
        sync_node(session, node)
        logs.append('порты подтянуты')
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        logs.append(str(exc))
    if node.id is not None:
        all_tpl = session.exec(
            select(InboundTemplate).where(InboundTemplate.enabled == True)  # noqa: E712
        ).all()
        set_node_template_ids(
            session,
            node.id,
            [t.id for t in all_tpl if t.id is not None],
        )
    return {'node': _node_out(node, session), 'logs': logs}


@router.post('/nodes/{node_id}/test')
def test_node(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        with XuiClient(node) as xui:
            xui.login()
            status = {}
            try:
                status = xui.server_status()
            except XuiError:
                status = {}
            try:
                apply_sub_settings(node, xui.panel_settings())
            except XuiError:
                pass
        node.last_error = ''
        session.add(node)
        session.commit()
        return {'ok': True, 'status': status}
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        return {'ok': False, 'error': str(exc)}


@router.post('/nodes/{node_id}/sync')
def api_sync_node(node_id: int, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    try:
        rows = sync_node(session, node)
        return {'ok': True, 'count': len(rows)}
    except XuiError as exc:
        node.last_error = str(exc)
        session.add(node)
        session.commit()
        raise HTTPException(400, str(exc)) from exc


class ProvisionIn(BaseModel):
    template_ids: list[int] = Field(default_factory=list)


@router.post('/nodes/{node_id}/provision')
def api_provision_node(node_id: int, session: SessionDep, body: ProvisionIn | None = None) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    ids = (body.template_ids if body else None) or []
    if ids:
        templates = session.exec(
            select(InboundTemplate).where(
                InboundTemplate.enabled == True,  # noqa: E712
                InboundTemplate.id.in_(ids),
            )
        ).all()
    else:
        templates = templates_for_node(session, node)
    if not templates:
        raise HTTPException(400, 'На сервере не выбраны входы — отметьте шаблоны в списке «Входы»')
    logs = provision_templates(session, node, templates)
    return {'ok': True, 'logs': logs}


@router.patch('/nodes/{node_id}')
def patch_node(node_id: int, body: NodePatch, session: SessionDep) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    data = body.model_dump(exclude_unset=True)
    if data.get('api_token') == '':
        data.pop('api_token')
    if data.get('flag'):
        data['flag'] = to_iso(data['flag']) or data['flag']
    if 'panel_url' in data and data['panel_url'] is not None:
        data['panel_url'] = normalize_panel_url(data['panel_url'])
        if not data.get('public_host'):
            data['public_host'] = public_host_from_url(data['panel_url'])
    template_ids = data.pop('template_ids', None)
    for key, value in data.items():
        setattr(node, key, value)
    session.add(node)
    session.commit()
    session.refresh(node)
    if template_ids is not None and node.id is not None:
        set_node_template_ids(session, node.id, template_ids)
    return _node_out(node, session)


@router.delete('/nodes/{node_id}')
def delete_node(node_id: int, session: SessionDep, wipe_remote: bool = False) -> dict:
    node = session.get(Node, node_id)
    if not node:
        raise HTTPException(404, 'node not found')
    from app.models import ClientPlacement, NodeTemplateAssignment

    for row in session.exec(
        select(NodeTemplateAssignment).where(NodeTemplateAssignment.node_id == node_id)
    ).all():
        session.delete(row)
    inbounds = session.exec(select(NodeInbound).where(NodeInbound.node_id == node_id)).all()
    placements = session.exec(select(ClientPlacement).where(ClientPlacement.node_id == node_id)).all()
    for row in placements:
        session.delete(row)
    if wipe_remote:
        try:
            with XuiClient(node) as xui:
                for inbound in inbounds:
                    try:
                        xui.del_inbound(inbound.xui_inbound_id)
                    except XuiError:
                        pass
        except XuiError:
            pass
    for inbound in inbounds:
        session.delete(inbound)
    session.delete(node)
    session.commit()
    return {'ok': True}


@router.get('/nodes/{node_id}/inbounds')
def list_inbounds(node_id: int, session: SessionDep) -> list[dict]:
    rows = session.exec(select(NodeInbound).where(NodeInbound.node_id == node_id)).all()
    return [row.model_dump() for row in rows]


@router.patch('/inbounds/{inbound_id}')
def patch_inbound(inbound_id: int, body: InboundPatch, session: SessionDep) -> dict:
    row = session.get(NodeInbound, inbound_id)
    if not row:
        raise HTTPException(404, 'inbound not found')
    data = body.model_dump(exclude_unset=True)
    push_panel = data.pop('push_panel', body.push_panel)
    names = None
    if 'server_names' in data and data['server_names'] is not None:
        names = split_csv(data['server_names'])
        data['server_names'] = ','.join(names)
    for key, value in data.items():
        setattr(row, key, value)
    session.add(row)
    session.commit()
    session.refresh(row)
    pushed = None
    push_error = ''
    if names is not None and push_panel:
        node = session.get(Node, row.node_id)
        if node:
            try:
                push_server_names(node, row, names)
                pushed = True
            except XuiError as exc:
                pushed = False
                push_error = str(exc)
    out = row.model_dump()
    out['pushed_to_panel'] = pushed
    out['push_error'] = push_error
    return out


class DestSniIn(BaseModel):
    dest: str


@router.post('/dest-sni')
def dest_sni(body: DestSniIn) -> dict:
    try:
        parse_dest(body.dest)
        return fetch_dest_sni(body.dest)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get('/templates')
def list_templates(session: SessionDep) -> list[dict]:
    return [t.model_dump() for t in session.exec(select(InboundTemplate)).all()]


@router.post('/templates')
def create_template(body: TemplateIn, session: SessionDep) -> dict:
    row = InboundTemplate(**body.model_dump())
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.model_dump()


@router.put('/templates/{template_id}')
def update_template(template_id: int, body: TemplateIn, session: SessionDep) -> dict:
    row = session.get(InboundTemplate, template_id)
    if not row:
        raise HTTPException(404, 'template not found')
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row.model_dump()


@router.delete('/templates/{template_id}')
def delete_template(template_id: int, session: SessionDep) -> dict:
    row = session.get(InboundTemplate, template_id)
    if not row:
        raise HTTPException(404)
    session.delete(row)
    session.commit()
    return {'ok': True}


def _client_out(session, client: Client, public_base: str) -> dict:
    placements = []
    from app.models import ClientPlacement

    placements = session.exec(
        select(ClientPlacement).where(ClientPlacement.client_id == client.id)
    ).all()
    ok = sum(1 for p in placements if p.ok)
    return {
        **client.model_dump(),
        'days_left': days_left(client),
        'sub_url': client_sub_url(client),
        'placements_ok': ok,
        'placements_total': len(placements),
    }


@router.get('/clients')
def list_clients(session: SessionDep) -> list[dict]:
    from app.settings import settings

    rows = session.exec(select(Client).order_by(Client.id.desc())).all()
    return [_client_out(session, c, settings.public_base_url) for c in rows]


@router.post('/clients')
def create_client(body: ClientIn, session: SessionDep) -> dict:
    from app.settings import settings

    slug_base = slugify(body.name)
    slug = slug_base
    n = 1
    while session.exec(select(Client).where(Client.slug == slug)).first():
        n += 1
        slug = f'{slug_base}{n}'
    client = Client(
        name=body.name.strip(),
        slug=slug,
        uuid=new_uuid(),
        sub_token=new_token(),
        expire_at=expire_from_days(body.days),
        traffic_limit_bytes=body.traffic_gb * 1024 * 1024 * 1024 if body.traffic_gb else 0,
        limit_ip=body.limit_ip,
        note=body.note,
        enable=True,
    )
    session.add(client)
    session.commit()
    session.refresh(client)
    logs = provision_client(session, client)
    return {'client': _client_out(session, client, settings.public_base_url), 'logs': logs}


@router.patch('/clients/{client_id}')
def patch_client(client_id: int, body: ClientPatch, session: SessionDep) -> dict:
    from app.settings import settings

    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404)
    if body.name is not None:
        client.name = body.name
    if body.enable is not None:
        client.enable = body.enable
    if body.note is not None:
        client.note = body.note
    if body.limit_ip is not None:
        client.limit_ip = body.limit_ip
    if body.traffic_gb is not None:
        client.traffic_limit_bytes = body.traffic_gb * 1024 * 1024 * 1024
    if body.days is not None:
        client.expire_at = expire_from_days(body.days)
    if body.add_days:
        now = datetime.now(timezone.utc)
        base = client.expire_at or now
        if base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)
        if base < now:
            base = now
        client.expire_at = base + timedelta(days=body.add_days)
    session.add(client)
    session.commit()
    logs = provision_client(session, client)
    session.refresh(client)
    return {'client': _client_out(session, client, settings.public_base_url), 'logs': logs}


@router.post('/clients/reconcile')
def reconcile_all_clients(session: SessionDep) -> dict:
    logs = reconcile_clients(session)
    return {'ok': True, 'logs': logs}


@router.post('/clients/{client_id}/provision')
def retry_client(client_id: int, session: SessionDep) -> dict:
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404)
    logs = provision_client(session, client)
    return {'ok': True, 'logs': logs}


@router.delete('/clients/{client_id}')
def api_delete_client(client_id: int, session: SessionDep) -> dict:
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404)
    logs = delete_client_remote(session, client)
    session.delete(client)
    session.commit()
    return {'ok': True, 'logs': logs}


@router.get('/clients/{client_id}/preview')
def preview_client(client_id: int, session: SessionDep) -> dict:
    client = session.get(Client, client_id)
    if not client:
        raise HTTPException(404)
    return {'yaml': render_profile(session, client)}


@router.get('/config')
def get_config(session: SessionDep) -> dict:
    doc = session.exec(select(ConfigDoc)).first()
    if not doc:
        raise HTTPException(404)
    return doc.model_dump()


@router.put('/config')
def put_config(body: ConfigIn, session: SessionDep) -> dict:
    from app.models import utcnow

    doc = session.exec(select(ConfigDoc)).first()
    if not doc:
        doc = ConfigDoc(yaml_text=body.yaml_text)
        session.add(doc)
    else:
        doc.yaml_text = body.yaml_text
        if body.pool_group_names is not None:
            doc.pool_group_names = body.pool_group_names
        if body.global_extra_snis is not None:
            doc.global_extra_snis = body.global_extra_snis
        doc.updated_at = utcnow()
        session.add(doc)
    session.commit()
    session.refresh(doc)
    return doc.model_dump()


@router.get('/stats')
def stats(session: SessionDep) -> dict:
    nodes = session.exec(select(Node)).all()
    clients = session.exec(select(Client)).all()
    return {
        'nodes': len(nodes),
        'nodes_enabled': sum(1 for n in nodes if n.enabled),
        'clients': len(clients),
        'clients_active': sum(1 for c in clients if not is_expired(c)),
        'expiring': [
            {'id': c.id, 'name': c.name, 'days_left': days_left(c)}
            for c in clients
            if c.expire_at and not is_expired(c) and days_left(c).isdigit() and int(days_left(c)) <= 7
        ],
    }


@router.get('/overview')
def overview(session: SessionDep) -> dict:
    from app.settings import settings

    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    clients = session.exec(select(Client).order_by(Client.id.desc())).all()
    inbound_counts = {
        node.id: len(session.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).all())
        for node in nodes
    }
    probes = probe_nodes(nodes)
    node_out = []
    for node in nodes:
        probe = probes.get(node.id or 0) or {}
        online = bool(probe.get('online'))
        if online:
            node.last_error = ''
        elif probe.get('error'):
            node.last_error = str(probe.get('error'))[:500]
        session.add(node)
        st = probe.get('status') or {}
        node_out.append(
            {
                **_node_out(node, session),
                'online': online,
                'cpu': st.get('cpu'),
                'mem_used': st.get('mem_used'),
                'mem_total': st.get('mem_total'),
                'uptime': st.get('uptime'),
                'xray': st.get('xray'),
                'tcp': st.get('tcp'),
                'udp': st.get('udp'),
                'inbound_count': probe.get('inbound_count') or inbound_counts.get(node.id, 0),
                'probe_error': probe.get('error') or '',
            }
        )
    session.commit()

    client_out = []
    for client in clients:
        usage = aggregate_client_usage(client, nodes, probes)
        limit = client.traffic_limit_bytes or 0
        client_out.append(
            {
                **_client_out(session, client, settings.public_base_url),
                'expired': is_expired(client),
                'up': usage['up'],
                'down': usage['down'],
                'used': usage['used'],
                'used_label': format_bytes(usage['used']),
                'limit_label': format_bytes(limit) if limit else 'без лимита',
                'online_nodes': usage['online_nodes'],
                'seen_on_nodes': usage['seen_on_nodes'],
            }
        )
    return {'nodes': node_out, 'clients': client_out}
