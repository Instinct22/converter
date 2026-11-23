from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlmodel import select

from app.deps import SessionDep
from app.mihomo import days_left, is_expired, render_profile, subscription_headers
from app.models import Client, Node
from app.overview import aggregate_client_usage, probe_nodes_presence
from app.settings import ROOT
from app.sub_link import client_sub_url
from app.util import format_bytes, ru_days
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=str(ROOT / 'app' / 'templates'))

_CLIENT_UA = re.compile(
    r'(clash|mihomo|meta|flclash|stash|surge|quantumult|loon|shadowrocket|'
    r'v2ray|sing-box|hiddify|nekobox|dhq|verge|clashx|clash\.meta)',
    re.I,
)
_BROWSER_UA = re.compile(r'(mozilla|chrome|safari|firefox|edg|opera|msie)', re.I)


def wants_subscription_html(request: Request) -> bool:
    if request.query_params.get('yaml') in {'1', 'true'}:
        return False
    if request.query_params.get('html') in {'1', 'true'}:
        return True
    ua = request.headers.get('user-agent') or ''
    if _CLIENT_UA.search(ua):
        return False
    accept = (request.headers.get('accept') or '').lower()
    if 'text/html' in accept and 'text/yaml' not in accept:
        return True
    return bool(_BROWSER_UA.search(ua))


def _usage_bundle(session, client: Client, *, presence: bool = True) -> dict:
    nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
    usage = aggregate_client_usage(client, nodes, probe_nodes_presence(nodes, include_online=presence))
    limit = client.traffic_limit_bytes or 0
    used = usage['used']
    left = days_left(client)
    return {
        **usage,
        'limit': limit,
        'used_label': format_bytes(used),
        'limit_label': format_bytes(limit) if limit else 'без лимита',
        'expire_label': '∞' if left == '∞' else ru_days(int(left)) if left.isdigit() else left,
        'expired': is_expired(client),
    }


def serve_yaml(token: str, session: SessionDep) -> PlainTextResponse:
    client = session.exec(select(Client).where(Client.sub_token == token)).first()
    if client is None:
        raise HTTPException(status_code=404, detail='unknown subscription')
    if is_expired(client):
        raise HTTPException(status_code=403, detail='subscription expired')
    usage = _usage_bundle(session, client, presence=False)
    body = render_profile(session, client)
    return PlainTextResponse(
        body,
        media_type='text/yaml; charset=utf-8',
        headers=subscription_headers(
            client,
            upload=usage['up'],
            download=usage['down'],
        ),
    )


def serve_html(token: str, session: SessionDep, request: Request) -> HTMLResponse:
    client = session.exec(select(Client).where(Client.sub_token == token)).first()
    if client is None:
        raise HTTPException(status_code=404, detail='unknown subscription')
    usage = _usage_bundle(session, client)
    from app.settings import settings

    mihomo_url = f'{settings.public_base_url.rstrip("/")}/mihomo/{client.sub_token}'
    sub_url = client_sub_url(client)
    return templates.TemplateResponse(
        request, 'sub_page.html',
        {
            'request': request,
            'client': client,
            'sub_url': sub_url,
            'yaml_url': sub_url + ('&yaml=1' if '?' in sub_url else '?yaml=1'),
            'mihomo_url': mihomo_url,
            **usage,
        },
    )


def serve_provider_yaml(token: str, key: str, session: SessionDep) -> PlainTextResponse:
    import yaml

    from app.mihomo import published_proxies, subscription_inputs

    if not re.fullmatch(r'[a-z0-9-]{1,64}', key or ''):
        raise HTTPException(status_code=404, detail='unknown provider')
    client = session.exec(select(Client).where(Client.sub_token == token)).first()
    if client is None:
        raise HTTPException(status_code=404, detail='unknown subscription')
    if is_expired(client):
        raise HTTPException(status_code=403, detail='subscription expired')
    nodes, inbound_map = subscription_inputs(session)
    proxies = [proxy for name, proxy in published_proxies(nodes, client, inbound_map) if name == key]
    if not proxies:
        raise HTTPException(status_code=404, detail='unknown provider')
    body = yaml.dump(
        {'proxies': proxies},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )
    return PlainTextResponse(body, media_type='text/yaml; charset=utf-8')


def serve_sub(token: str, session: SessionDep, request: Request):
    if wants_subscription_html(request):
        return serve_html(token, session, request)
    return serve_yaml(token, session)


@router.get('/mihomo/{token}')
def mihomo_sub(token: str, session: SessionDep) -> PlainTextResponse:
    return serve_yaml(token, session)


@router.get('/clash/{token}')
@router.get('/sub/{token}')
def clash_sub(token: str, session: SessionDep, request: Request):
    return serve_sub(token, session, request)
