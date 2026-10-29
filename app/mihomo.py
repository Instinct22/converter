from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any

import yaml
from sqlmodel import Session, select

from app.models import Client, ConfigDoc, Node, NodeInbound
from app.provision import split_csv

def _block_pattern(name: str) -> re.Pattern[str]:
    begin = r'# \{\{XUI_' + name + r'_BEGIN\}\}'
    end = r'# \{\{XUI_' + name + r'_END\}\}'
    return re.compile(r'(?m)^[ \t]*' + begin + r'.*?' + r'^[ \t]*' + end, re.S)


def replace_block(text: str, name: str, lines: list[str]) -> str:
    pattern = _block_pattern(name)

    def repl(match: re.Match[str]) -> str:
        marker_line = match.group(0).split('\n', 1)[0]
        indent = re.match(r'\s*', marker_line).group(0)
        if not lines:
            return ''
        body = ''.join(f'{indent}{line.rstrip()}\n' for line in lines)
        return body.rstrip('\n')

    return pattern.sub(repl, text)


def provider_name(node: Node) -> str:
    raw = (node.clash_name or node.name or f'node-{node.id}').lower()
    slug = re.sub(r'[^a-z0-9]+', '-', raw).strip('-') or f'node-{node.id}'
    return f'n{node.id}-{slug}'[:48]


def node_clash_sub_base(node: Node) -> str:
    scheme = (node.sub_scheme or 'https').strip().rstrip(':/') or 'https'
    host = (node.public_host or '').strip()
    port = int(node.sub_port or 2096)
    path = (node.sub_clash_path or node.sub_path or 'clash').strip('/')
    if not host:
        return ''
    return f'{scheme}://{host}:{port}/{path}'


def node_clash_sub_url(node: Node, sub_id: str) -> str:
    base = node_clash_sub_base(node)
    if not base:
        return ''
    return f'{base}/{sub_id}'


def dump_providers(nodes: list[Node], sub_id: str) -> list[str]:
    lines: list[str] = []
    for node in nodes:
        if not (node.public_host or '').strip():
            continue
        key = provider_name(node)
        url = node_clash_sub_url(node, sub_id)
        prefix = node.clash_prefix()
        extra = f'{prefix} | ' if prefix else ''
        lines.extend(
            [
                f'{key}:',
                '  type: http',
                f'  url: {json.dumps(url)}',
                f'  path: ./providers/{key}.yaml',
                '  interval: 3600',
                '  override:',
                f'    additional-prefix: {json.dumps(extra, ensure_ascii=False)}',
                '  health-check:',
                '    enable: true',
                '    url: https://cp.cloudflare.com/generate_204',
                '    interval: 300',
                '    lazy: false',
                "    expected-status: '204'",
            ]
        )
    return lines or ['{}']


def dump_proxies(proxies: list[dict[str, Any]]) -> list[str]:
    if not proxies:
        return ['[]']
    lines: list[str] = []
    for proxy in proxies:
        dumped = yaml.dump(
            proxy,
            allow_unicode=True,
            sort_keys=False,
            default_flow_style=False,
            indent=2,
            width=1000,
        )
        item = [line for line in dumped.rstrip().split('\n') if line]
        if not item:
            continue
        lines.append(f'- {item[0]}')
        lines.extend(f'  {line}' for line in item[1:])
    return lines


def node_ip(node: Node) -> str | None:
    host = (node.public_host or '').strip()
    if not host:
        return None
    host = host.split('/')[0]
    if ':' in host and not host.startswith('['):
        # hostname:port is not used; public_host should be IP or domain
        maybe_ip = host.split(':')[0]
        host = maybe_ip
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


def published_snis(inbound: NodeInbound, global_extra: list[str] | None = None) -> list[str]:
    ordered: list[str] = []
    for item in split_csv(inbound.server_names):
        if item and item not in ordered:
            ordered.append(item)
    return ordered or ['']


def sni_label(sni: str) -> str:
    if not sni:
        return 'default'
    parts = sni.split('.')
    return parts[0] if parts else sni


def build_proxy(
    *,
    name: str,
    node: Node,
    inbound: NodeInbound,
    client: Client,
    servername: str,
) -> dict[str, Any] | None:
    if inbound.protocol != 'vless' or not inbound.public_key:
        return None
    proxy: dict[str, Any] = {
        'name': name,
        'type': 'vless',
        'server': node.public_host.strip(),
        'port': inbound.port,
        'uuid': client.uuid,
        'tls': True,
        'udp': True,
        'servername': servername,
        'client-fingerprint': inbound.fingerprint or 'chrome',
        'network': inbound.network or 'tcp',
        'reality-opts': {
            'public-key': inbound.public_key,
            'short-id': inbound.short_id or '',
        },
    }
    if inbound.network == 'grpc':
        proxy['grpc-opts'] = {'grpc-service-name': inbound.grpc_service_name or ''}
    elif inbound.network in {'xhttp', 'splithttp'}:
        proxy['network'] = 'xhttp'
        proxy['xhttp-opts'] = {'path': inbound.xhttp_path or '/', 'mode': 'auto'}
    elif inbound.flow:
        proxy['flow'] = inbound.flow
    return proxy


def collect_proxies(
    session: Session,
    client: Client,
    global_extra: list[str],
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    nodes = session.exec(
        select(Node).where(Node.enabled.is_(True)).order_by(Node.sort_order, Node.id)
    ).all()
    proxies: list[dict[str, Any]] = []
    names: list[str] = []
    cidrs: list[str] = []
    used_names: set[str] = set()
    for node in nodes:
        ip = node_ip(node)
        if ip:
            cidrs.append(f'{ip}/32')
        inbounds = session.exec(
            select(NodeInbound).where(NodeInbound.node_id == node.id)
        ).all()
        for inbound in inbounds:
            prefix = inbound.display_prefix or node.clash_prefix()
            snis = published_snis(inbound, global_extra)
            multi = len(snis) > 1 or len(inbounds) > 1
            for index, sni in enumerate(snis):
                if multi:
                    name = f'{prefix} | {inbound.port}'
                    if index > 0 or len(snis) > 1:
                        name = f'{prefix} | {inbound.port} | {sni_label(sni)}'
                else:
                    name = prefix
                if name in used_names:
                    name = f'{name} | {inbound.xui_inbound_id}'
                used_names.add(name)
                proxy = build_proxy(
                    name=name,
                    node=node,
                    inbound=inbound,
                    client=client,
                    servername=sni or (split_csv(inbound.server_names) or [''])[0],
                )
                if proxy:
                    proxies.append(proxy)
                    names.append(name)
    return proxies, names, cidrs


def render_profile(session: Session, client: Client) -> str:
    doc = session.exec(select(ConfigDoc)).first()
    if doc is None:
        raise RuntimeError('config template is missing')
    nodes = session.exec(
        select(Node).where(Node.enabled.is_(True)).order_by(Node.sort_order, Node.id)
    ).all()
    cidrs: list[str] = []
    provider_nodes: list[Node] = []
    for node in nodes:
        ip = node_ip(node)
        if ip:
            cidrs.append(f'{ip}/32')
        if (node.public_host or '').strip():
            provider_nodes.append(node)
    names = [provider_name(node) for node in provider_nodes]
    text = doc.yaml_text
    if 'XUI_PROVIDERS_BEGIN' in text:
        text = replace_block(text, 'PROVIDERS', dump_providers(provider_nodes, client.sub_token))
        pool_lines = [f'- {name}' for name in names]
        text = replace_block(text, 'POOL', pool_lines)
    else:
        proxies, proxy_names, extra_cidrs = collect_proxies(session, client, [])
        for item in extra_cidrs:
            if item not in cidrs:
                cidrs.append(item)
        text = replace_block(text, 'PROXIES', dump_proxies(proxies) if proxies else ['[]'])
        pool_lines = [f'- {n}' for n in proxy_names] if proxy_names else ['- DIRECT']
        text = replace_block(text, 'POOL', pool_lines)
    if 'XUI_PROXIES_BEGIN' in doc.yaml_text and 'XUI_PROVIDERS_BEGIN' in doc.yaml_text:
        text = replace_block(text, 'PROXIES', ['[]'])
    cidr_lines = [f'- {c}' for c in cidrs]
    text = replace_block(text, 'TUN_EXCLUDE', cidr_lines or ['[]'])
    rule_lines = [f'- IP-CIDR,{c},DIRECT,no-resolve' for c in cidrs]
    text = replace_block(text, 'CIDRS', rule_lines)
    return text


def subscription_headers(
    client: Client,
    *,
    upload: int = 0,
    download: int = 0,
) -> dict[str, str]:
    expire = 0
    if client.expire_at:
        expire = int(client.expire_at.timestamp())
    userinfo = (
        f'upload={int(upload)}; download={int(download)}; '
        f'total={client.traffic_limit_bytes or 0}; expire={expire}'
    )
    from app.settings import settings
    from app.sub_link import client_sub_url

    return {
        'subscription-userinfo': userinfo,
        'profile-update-interval': '1',
        'profile-title': f'base64:{_b64_title(client.name)}',
        'profile-web-page-url': settings.public_base_url.rstrip('/'),
        'content-disposition': f'inline; filename="{client.slug}.yaml"',
        'profile-url': client_sub_url(client),
    }


def _b64_title(name: str) -> str:
    import base64

    return base64.b64encode(name.encode('utf-8')).decode('ascii')


def days_left(client: Client) -> str:
    if not client.expire_at:
        return '∞'
    now = datetime.now(timezone.utc)
    expire = client.expire_at
    if expire.tzinfo is None:
        expire = expire.replace(tzinfo=timezone.utc)
    seconds = (expire - now).total_seconds()
    if seconds <= 0:
        return '0'
    return str(int((seconds + 86399) // 86400))


def is_expired(client: Client) -> bool:
    if not client.enable:
        return True
    if not client.expire_at:
        return False
    expire = client.expire_at
    if expire.tzinfo is None:
        expire = expire.replace(tzinfo=timezone.utc)
    return expire <= datetime.now(timezone.utc)
