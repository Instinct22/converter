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
from app.settings import settings

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
    path = (node.sub_clash_path or '').strip().strip('/')
    if not host or not path:
        return ''
    return f'{scheme}://{host}:{port}/{path}'


def node_clash_sub_url(node: Node, sub_id: str) -> str:
    base = node_clash_sub_base(node)
    if not base:
        return ''
    return f'{base}/{sub_id}'


def _health_lines(*, lazy: bool = False) -> list[str]:
    return [
        '  health-check:',
        '    enable: true',
        '    url: https://cp.cloudflare.com/generate_204',
        '    interval: 300',
        f'    lazy: {"true" if lazy else "false"}',
        "    expected-status: '204'",
    ]


def _provider_slug(node: Node, extra: str = '') -> str:
    base = provider_name(node)
    if not extra:
        return base
    tail = re.sub(r'[^a-z0-9]+', '-', extra.lower()).strip('-') or 'sni'
    return f'{base}-{tail}'[:64]


def _y(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _override_expr_line(expression: str) -> str:
    """Mihomo/DHQ expect ``- '.name = \"…\"'`` (see test11), not JSON-escaped strings."""
    inner = expression.replace("'", "''")
    return f"      - '{inner}'"


def _filter_yaml(filt: str) -> str:
    """Mihomo filters raw sub proxy names by regex (before override)."""
    if filt in {'8443', '443', '443-'}:
        return f"  filter: '{filt}'"
    if filt.startswith('^') or filt.startswith('('):
        return f"  filter: '{filt}'"
    return f'  filter: {_y(filt)}'


def _provider_cache_path(key: str, sub_id: str) -> str:
    """Unique file per client sub token so Mihomo refetches after reprovision."""
    slug = re.sub(r'[^a-z0-9]+', '', (sub_id or '').lower())[:12] or 'sub'
    return f'./providers/{key}-{slug}-p2.yaml'


def _provider_block(
    *,
    key: str,
    url: str,
    sub_id: str,
    filt: str | None = None,
    exclude_filter: str | None = None,
    prefix: str | None = None,
    suffix: str | None = None,
    expr: list[str] | None = None,
    lazy: bool = False,
) -> list[str]:
    lines = [
        f'{key}:',
        f'  name: {key}',
        '  type: http',
        f'  url: {_y(url)}',
        f'  path: {_y(_provider_cache_path(key, sub_id))}',
        '  interval: 3600',
    ]
    if filt:
        lines.append(_filter_yaml(filt))
    if exclude_filter:
        lines.append(f"  exclude-filter: '{exclude_filter}'")
    if prefix or suffix or expr:
        lines.append('  override:')
        if prefix:
            lines.append(f'    additional-prefix: {_y(prefix)}')
        if suffix:
            lines.append(f'    additional-suffix: {_y(suffix)}')
        if expr:
            lines.append('    override-expr:')
            for item in expr:
                lines.append(_override_expr_line(item))
    lines.extend(_health_lines(lazy=lazy))
    return lines


def _is_alt_inbound(inbound: NodeInbound) -> bool:
    if inbound.port == 8443:
        return True
    return (inbound.network or '') in {'xhttp', 'splithttp'}


def _reg_domain(host: str) -> str:
    parts = [part for part in host.split(':')[0].lower().split('.') if part]
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return host.lower()


def inbound_sni_chain(inbound: NodeInbound) -> list[str]:
    """SNI variants for extra proxy-providers (override ``servername``).

    When ``snis_locked`` (после шаблона Master) — только primary + ``extra_snis``,
    без клонов по всему SAN из панели. Иначе — primary и SAN того же registrable
    domain, плюс явные ``extra_snis``.
    """
    snis = [item for item in published_snis(inbound) if item]
    if not snis:
        return ['']
    primary = snis[0]
    out = [primary]
    seen = {primary.lower()}
    allowed_extra = {item.lower() for item in split_csv(inbound.extra_snis)}
    for sni in split_csv(inbound.extra_snis):
        key = sni.lower()
        if key and key not in seen:
            out.append(sni)
            seen.add(key)
    if inbound.snis_locked:
        return out
    root = _reg_domain(primary)
    for sni in snis[1:]:
        key = sni.lower()
        if key in seen:
            continue
        if key in allowed_extra or _reg_domain(sni) == root:
            out.append(sni)
            seen.add(key)
    return out


def port_name_filters(inbound: NodeInbound, has_alt: bool) -> tuple[str | None, str | None]:
    """Фильтры по сырому ``name`` из Clash-подписки (см. Clash.Meta NewProxiesParser).

    3x-ui: ``443-<slug>``, ``8443``, иногда лишние inbounds (``test``, tcp). Паттерн
    ``443`` матчит и ``8443``; ``443-`` / ``^443-`` — только основной grpc inbound.
    """
    if _is_alt_inbound(inbound):
        return '8443', None
    return '443-', '8443' if has_alt else None


def _publishable_inbound(inbound: NodeInbound) -> bool:
    """Only standard template ports go to Mihomo (skip test/tcp junk on panel)."""
    if not inbound.use_in_sub:
        return False
    return inbound.port in {443, 8443}


def dump_providers(
    nodes: list[Node],
    sub_id: str,
    inbound_map: dict[int, list[NodeInbound]] | None = None,
) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    keys: list[str] = []
    used: set[str] = set()

    def take_key(raw: str) -> str:
        key = raw or 'node'
        n = 2
        while key in used:
            key = f'{raw}-{n}'[:64]
            n += 1
        used.add(key)
        return key

    for node in nodes:
        if not (node.public_host or '').strip():
            continue
        url = node_clash_sub_url(node, sub_id)
        if not url:
            continue
        prefix = node.clash_prefix()
        inbounds = [
            row
            for row in (inbound_map or {}).get(node.id, [])
            if _publishable_inbound(row)
        ]
        inbounds.sort(key=lambda row: (row.port, row.id or 0))
        if not inbounds:
            key = take_key(provider_name(node))
            keys.append(key)
            lines.extend(
                _provider_block(
                    key=key,
                    url=url,
                    sub_id=sub_id,
                    expr=[f'.name = "{prefix}"'] if prefix else None,
                )
            )
            continue
        has_alt = any(_is_alt_inbound(row) for row in inbounds)
        primary_emitted = False
        for inbound in inbounds:
            snis = inbound_sni_chain(inbound)
            display = (inbound.display_prefix or prefix).strip() or prefix
            filt, exclude = port_name_filters(inbound, has_alt)
            if _is_alt_inbound(inbound):
                tag = (inbound.provider_label or 'yahoo').strip() or 'yahoo'
                # test11 / DHQ: one alt-port provider; extras only via extra_snis
                key = take_key(_provider_slug(node, tag))
                keys.append(key)
                lines.extend(
                    _provider_block(
                        key=key,
                        url=url,
                        sub_id=sub_id,
                        filt=filt,
                        expr=[f'.name = "{display} | {tag}"'],
                    )
                )
                for sni in split_csv(inbound.extra_snis):
                    label = sni_label(sni)
                    key = take_key(_provider_slug(node, f'{tag}-{label}'))
                    keys.append(key)
                    pretty = f'{display} | {tag} | {label}'
                    lines.extend(
                        _provider_block(
                            key=key,
                            url=url,
                            sub_id=sub_id,
                            filt=filt,
                            expr=[
                                f'.servername = "{sni}"',
                                f'.name = "{pretty}"',
                            ],
                        )
                    )
                continue
            if not primary_emitted:
                key = take_key(provider_name(node))
                primary_emitted = True
            else:
                key = take_key(_provider_slug(node, str(inbound.port)))
            keys.append(key)
            port_tag = (inbound.provider_label or '').strip()
            primary_label = f'{display} | {port_tag}' if port_tag else display
            lines.extend(
                _provider_block(
                    key=key,
                    url=url,
                    sub_id=sub_id,
                    filt=filt,
                    exclude_filter=exclude,
                    expr=[f'.name = "{primary_label}"'],
                )
            )
            for sni in snis[1:]:
                label = sni_label(sni)
                key = take_key(_provider_slug(node, label))
                keys.append(key)
                pretty = f'{display} | {label}'
                lines.extend(
                    _provider_block(
                        key=key,
                        url=url,
                        sub_id=sub_id,
                        filt=filt,
                        exclude_filter=exclude,
                        expr=[
                            f'.servername = "{sni}"',
                            f'.name = "{pretty}"',
                        ],
                    )
                )
    return (lines or ['{}'], keys)


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


def profile_direct_cidrs(nodes: list[Node]) -> list[str]:
    """IPs that must bypass TUN/rules (node panels + Master sub host)."""
    seen: set[str] = set()
    out: list[str] = []
    for node in nodes:
        ip = node_ip(node)
        if ip and ip not in seen:
            seen.add(ip)
            out.append(f'{ip}/32')
    base = (settings.public_base_url or '').strip()
    if base:
        from urllib.parse import urlparse

        host = (urlparse(base).hostname or '').strip()
        if host:
            try:
                ipaddress.ip_address(host)
                if host not in seen:
                    seen.add(host)
                    out.append(f'{host}/32')
            except ValueError:
                pass
    return out


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
    host = sni.split(':')[0].strip().lower()
    parts = [part for part in host.split('.') if part]
    if len(parts) >= 2 and parts[0] == 'www':
        return parts[1]
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
    provider_nodes: list[Node] = []
    for node in nodes:
        if (node.public_host or '').strip():
            provider_nodes.append(node)
    cidrs = profile_direct_cidrs(provider_nodes)
    inbound_map: dict[int, list[NodeInbound]] = {}
    for node in provider_nodes:
        inbound_map[node.id] = session.exec(
            select(NodeInbound).where(NodeInbound.node_id == node.id)
        ).all()
    text = doc.yaml_text
    if 'XUI_PROVIDERS_BEGIN' in text:
        provider_lines, names = dump_providers(
            provider_nodes, client.sub_token, inbound_map
        )
        text = replace_block(text, 'PROVIDERS', provider_lines)
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
