import json

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from sqlmodel import select

from app.deps import SessionDep, credentials_ok, request_authorized
from app.flags import COUNTRY_NAMES
from app.mihomo import days_left, is_expired
from app.models import Client, ConfigDoc, InboundTemplate, Node, NodeInbound
from app.settings import ROOT, settings
from app.provision import node_template_ids, split_csv
from app.routers.updates import release_groups
from app.sub_link import client_sub_url, sub_path
from app.util import ru_days
from app.xui import version_equal, version_newer


def unique_snis(*parts: str) -> list[str]:
    ordered: list[str] = []
    for part in parts:
        for item in split_csv(part):
            if item not in ordered:
                ordered.append(item)
    return ordered

def script_json(value) -> Markup:
    raw = json.dumps(value, ensure_ascii=False, default=str)
    raw = (
        raw.replace('&', '\\u0026')
        .replace('<', '\\u003c')
        .replace('>', '\\u003e')
        .replace('\u2028', '\\u2028')
        .replace('\u2029', '\\u2029')
    )
    return Markup(raw)


router = APIRouter()
templates = Jinja2Templates(directory=str(ROOT / 'app' / 'templates'))
templates.env.filters['tojson'] = lambda value: json.dumps(value, ensure_ascii=False, default=str)
templates.env.filters['script_json'] = script_json


def client_edit_payload(client: Client) -> dict:
    left = days_left(client)
    try:
        days = 0 if left == '∞' else int(left)
    except ValueError:
        days = 0
    return {
        'id': client.id,
        'name': client.name,
        'note': client.note or '',
        'limit_ip': client.limit_ip or 0,
        'enable': bool(client.enable) and not is_expired(client),
        'traffic_gb': int((client.traffic_limit_bytes or 0) // (1024 ** 3)),
        'days': days,
    }


def expire_label(client: Client) -> str:
    if is_expired(client):
        return 'доступ закрыт'
    left = days_left(client)
    if left == '∞':
        return 'без срока'
    return ru_days(int(left))


def _ctx(request: Request, **extra):
    data = {
        'request': request,
        'admin': request_authorized(request),
        'flash': request.session.pop('flash', ''),
        'public_base': settings.public_base_url,
        'sub_path': sub_path(),
        'client_sub_url': client_sub_url,
        'days_left': days_left,
        'is_expired': is_expired,
        'expire_label': expire_label,
        'client_edit_payload': client_edit_payload,
        'split_csv': split_csv,
        'unique_snis': unique_snis,
        'flag_names': COUNTRY_NAMES,
    }
    data.update(extra)
    return data


@router.get('/login', response_class=HTMLResponse)
def login_page(request: Request):
    if request_authorized(request):
        return RedirectResponse('/', status_code=302)
    return templates.TemplateResponse('login.html', _ctx(request))


@router.post('/login')
def login_post(request: Request, username: str = Form(...), password: str = Form(...)):
    if credentials_ok(username, password):
        request.session.clear()
        request.session['admin'] = True
        return RedirectResponse('/', status_code=302)
    request.session['flash'] = 'Неверный логин или пароль'
    return RedirectResponse('/login', status_code=302)


@router.get('/logout')
def logout(request: Request):
    request.session.clear()
    return RedirectResponse('/login', status_code=302)


def _need_admin(request: Request):
    if request_authorized(request):
        return None
    return RedirectResponse('/login', status_code=302)


def _ver_state(current: str, latest: str) -> str:
    """'update' — есть более новая версия; 'current' — версии равны; '' — данных нет."""
    if not current or not latest:
        return ''
    if version_newer(latest, current):
        return 'update'
    if version_equal(latest, current):
        return 'current'
    return ''


@router.get('/', response_class=HTMLResponse)
def dashboard(request: Request, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    clients = session.exec(select(Client).order_by(Client.id.desc())).all()
    inbound_counts = {
        node.id: len(session.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).all())
        for node in nodes
    }
    # Виджет «Входы» на обзоре: те же шаблоны, что выбираются у каждой ноды.
    templates_rows = session.exec(select(InboundTemplate)).all()
    node_templates: dict[int, list[int]] = {}
    for node in nodes:
        if node.id is None:
            continue
        node_templates[node.id] = node_template_ids(session, node.id)
    # Флаги «нужно обновление» считаем по числам версий (3.11 == 3.11.0), а не строками.
    update_flags = {
        node.id: {
            'panel': _ver_state(node.xui_version or '', node.panel_latest_version or ''),
            'xray': _ver_state(node.xray_version or '', node.xray_latest_version or ''),
        }
        for node in nodes
        if node.id is not None
    }
    return templates.TemplateResponse(
        'dashboard.html',
        _ctx(
            request,
            page='dashboard',
            nodes=nodes,
            clients=clients,
            active=sum(1 for c in clients if not is_expired(c)),
            nodes_enabled=sum(1 for n in nodes if n.enabled),
            inbound_counts=inbound_counts,
            inbound_templates=templates_rows,
            node_templates=node_templates,
            update_flags=update_flags,
        ),
    )


@router.get('/nodes')
def nodes_page(request: Request):
    if (redir := _need_admin(request)):
        return redir
    return RedirectResponse('/', status_code=302)


@router.get('/nodes/{node_id}', response_class=HTMLResponse)
def node_detail(request: Request, node_id: int, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    node = session.get(Node, node_id)
    if not node:
        return RedirectResponse('/', status_code=302)
    return templates.TemplateResponse(
        'node_detail.html',
        _ctx(request, page='dashboard', node=node),
    )


@router.get('/protection', response_class=HTMLResponse)
def protection_page(request: Request, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    from app.ssh_access import ensure_fleet_key, fingerprint, public_key_line

    from app.firewall import display_ports
    from app.reachability import inbound_ports

    ensure_fleet_key()
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    protecting = sum(1 for node in nodes if node.fail2ban_state == 'protecting')
    port_views = {
        node.id: display_ports(node, inbound_ports(session, int(node.id)))
        for node in nodes
        if node.id is not None
    }
    return templates.TemplateResponse(
        'protection.html',
        _ctx(
            request,
            page='protection',
            nodes=nodes,
            protecting=protecting,
            banned_now=sum(int(node.fail2ban_banned or 0) for node in nodes),
            banned_day=sum(int(node.fail2ban_day or 0) for node in nodes),
            key_fingerprint=fingerprint(),
            public_key=public_key_line(),
            port_views=port_views,
        ),
    )


@router.get('/releases', response_class=HTMLResponse)
def releases_page(request: Request):
    if (redir := _need_admin(request)):
        return redir
    groups = release_groups()
    return templates.TemplateResponse(
        'releases.html',
        _ctx(
            request,
            page='releases',
            groups=groups,
            on_disk=sum(1 for group in groups for row in group['files'] if row['on_disk']),
            current=next((group['version'] for group in groups if group['current']), '—'),
        ),
    )


@router.get('/clients')
def clients_page(request: Request):
    if (redir := _need_admin(request)):
        return redir
    return RedirectResponse('/', status_code=302)


@router.get('/templates', response_class=HTMLResponse)
def templates_page(request: Request, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    rows = session.exec(select(InboundTemplate)).all()
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    scan_nodes = [
        {'id': node.id, 'name': node.name, 'enabled': bool(node.enabled)}
        for node in nodes
    ]
    return templates.TemplateResponse(
        'templates.html',
        _ctx(
            request,
            page='templates',
            inbound_templates=rows,
            nodes=nodes,
            scan_nodes=scan_nodes,
        ),
    )


@router.get('/config', response_class=HTMLResponse)
def config_page(request: Request, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    doc = session.exec(select(ConfigDoc)).first()
    clients = session.exec(select(Client).order_by(Client.id.desc())).all()
    return templates.TemplateResponse(
        'config.html',
        _ctx(request, page='config', doc=doc, clients=clients),
    )
