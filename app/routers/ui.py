import json

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlmodel import select

from app.deps import SessionDep, WWW_AUTHENTICATE, request_authorized
from app.mihomo import days_left, is_expired
from app.models import Client, ConfigDoc, InboundTemplate, Node, NodeInbound
from app.settings import ROOT, settings
from app.provision import split_csv
from app.sub_link import client_sub_url, sub_path
from app.util import ru_days


def unique_snis(*parts: str) -> list[str]:
    ordered: list[str] = []
    for part in parts:
        for item in split_csv(part):
            if item not in ordered:
                ordered.append(item)
    return ordered

router = APIRouter()
templates = Jinja2Templates(directory=str(ROOT / 'app' / 'templates'))
templates.env.filters['tojson'] = lambda value: json.dumps(value, ensure_ascii=False, default=str)


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
        'flash': '',
        'public_base': settings.public_base_url,
        'sub_path': sub_path(),
        'client_sub_url': client_sub_url,
        'days_left': days_left,
        'is_expired': is_expired,
        'expire_label': expire_label,
        'client_edit_payload': client_edit_payload,
        'split_csv': split_csv,
        'unique_snis': unique_snis,
    }
    data.update(extra)
    return data


@router.get('/login')
def login_page():
    return Response(status_code=401, headers=WWW_AUTHENTICATE)


@router.get('/logout')
def logout():
    return Response(status_code=401, headers=WWW_AUTHENTICATE)


def _need_admin(request: Request):
    if request_authorized(request):
        return None
    return Response(status_code=401, headers=WWW_AUTHENTICATE)


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
        ),
    )


@router.get('/nodes', response_class=HTMLResponse)
def nodes_page(request: Request, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    templates_rows = session.exec(select(InboundTemplate)).all()
    counts = {}
    for node in nodes:
        counts[node.id] = len(
            session.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).all()
        )
    return templates.TemplateResponse(
        'nodes.html',
        _ctx(request, page='nodes', nodes=nodes, inbound_templates=templates_rows, inbound_counts=counts),
    )


@router.get('/nodes/{node_id}', response_class=HTMLResponse)
def node_detail(request: Request, node_id: int, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    node = session.get(Node, node_id)
    if not node:
        return RedirectResponse('/nodes', status_code=302)
    return templates.TemplateResponse(
        'node_detail.html',
        _ctx(request, page='nodes', node=node),
    )


@router.get('/clients', response_class=HTMLResponse)
def clients_page(request: Request, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    clients = session.exec(select(Client).order_by(Client.id.desc())).all()
    return templates.TemplateResponse(
        'clients.html',
        _ctx(
            request,
            page='clients',
            clients=clients,
            days_left=days_left,
            is_expired=is_expired,
        ),
    )


@router.get('/templates', response_class=HTMLResponse)
def templates_page(request: Request, session: SessionDep):
    if (redir := _need_admin(request)):
        return redir
    rows = session.exec(select(InboundTemplate)).all()
    nodes = session.exec(select(Node).order_by(Node.sort_order, Node.id)).all()
    return templates.TemplateResponse(
        'templates.html',
        _ctx(request, page='templates', inbound_templates=rows, nodes=nodes),
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
