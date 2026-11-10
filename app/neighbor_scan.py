from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.models import Node
from app.tls_sni import names_from_certificate

_PORT = 443
_TIMEOUT = 3.0
_WORKERS = 32
_DEADLINE = 70.0
_DNS_TIMEOUT = 4.0
_LOCK = threading.Lock()
_DNS_CACHE: dict[str, list[str]] = {}
_DNS_CACHE_LOCK = threading.Lock()


def hosts_in_slash24(address: str) -> tuple[str, list[str]]:
    ip = require_global_ipv4(address)
    network = ipaddress.ip_network(f'{ip}/24', strict=False)
    hosts = [str(item) for item in network.hosts() if item != ip]
    return str(network), hosts


def require_global_ipv4(value: str) -> ipaddress.IPv4Address:
    text = (value or '').strip()
    try:
        ip = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError('у сервера нет публичного IPv4') from exc
    if not isinstance(ip, ipaddress.IPv4Address):
        raise ValueError('поиск соседей умеет только IPv4')
    if not ip.is_global:
        raise ValueError('поиск соседей запускается только для публичного адреса сервера')
    return ip


def resolve_public_ipv4(host: str) -> str:
    text = (host or '').strip().rstrip('.')
    if not text:
        raise ValueError('у сервера нет публичного адреса')
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return str(require_global_ipv4(text))
    try:
        infos = socket.getaddrinfo(text, _PORT, socket.AF_INET, socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError('не удалось узнать IPv4 сервера') from exc
    for info in infos:
        candidate = info[4][0]
        try:
            return str(require_global_ipv4(candidate))
        except ValueError:
            continue
    raise ValueError('у сервера нет публичного IPv4')


def classify_hit(
    ip: str,
    *,
    tls13: bool,
    h2: bool,
    domain: str,
    wildcard_only: bool,
    issuer: str,
    resolved: list[str] | None,
) -> dict:
    row = {
        'ip': ip,
        'domain': domain or ('*' if wildcard_only else ''),
        'issuer': issuer,
        'dns': '',
        'keep': False,
        'why': '',
    }
    if not tls13 or not h2:
        missing = []
        if not tls13:
            missing.append('нет TLS 1.3')
        if not h2:
            missing.append('нет HTTP/2')
        row['dns'] = 'слабый TLS'
        row['why'] = ', '.join(missing)
        return row
    if wildcard_only or (domain or '').startswith('*.'):
        row['domain'] = domain or '*'
        row['dns'] = 'маска'
        row['why'] = 'подстановочное имя в цель не подставляем'
        return row
    if not domain or not issuer:
        row['dns'] = 'нет имени'
        row['why'] = 'в сертификате нет домена или издателя'
        return row
    if resolved is None:
        row['dns'] = 'нет DNS'
        row['why'] = 'имя из сертификата не резолвится'
        return row
    wanted = {item.split('%')[0] for item in resolved}
    if ip in wanted:
        row['dns'] = 'совпал'
        row['keep'] = True
        row['why'] = 'сайт в этой сети, имя указывает на этот адрес'
        return row
    row['dns'] = 'чужой IP'
    row['why'] = 'чужой сертификат: имя указывает на другой адрес'
    return row


def lookup_domain(domain: str) -> list[str] | None:
    key = (domain or '').strip().lower().rstrip('.')
    if not key or key.startswith('*.'):
        return None
    with _DNS_CACHE_LOCK:
        cached = _DNS_CACHE.get(key)
    if cached is not None:
        return list(cached)
    found = _lookup_uncached(key)
    if found is None:
        return None
    with _DNS_CACHE_LOCK:
        _DNS_CACHE[key] = list(found)
    return found


def scan_node_neighborhood(node: Node) -> dict:
    if not _LOCK.acquire(blocking=False):
        raise RuntimeError('поиск уже идёт')
    try:
        address = resolve_public_ipv4(node.public_host)
        cidr, hosts = hosts_in_slash24(address)
        hits = _probe_all(hosts)
        rows = _classify_hits(hits)
        kept = [row for row in rows if row['keep']]
        rejected = [row for row in rows if not row['keep']]
        return {
            'node_id': node.id,
            'name': node.name,
            'address': address,
            'cidr': cidr,
            'scanned': len(hosts),
            'kept': len(kept),
            'foreign_cert': sum(1 for row in rejected if row['dns'] == 'чужой IP'),
            'weak_tls': sum(1 for row in rejected if row['dns'] == 'слабый TLS'),
            'wildcard': sum(1 for row in rejected if row['dns'] == 'маска'),
            'rows': kept + rejected,
        }
    finally:
        _LOCK.release()


def _classify_hits(hits: list[dict]) -> list[dict]:
    domains = []
    for hit in hits:
        domain = hit.get('domain') or ''
        if hit.get('tls13') and hit.get('h2') and domain and not hit.get('wildcard_only'):
            domains.append(domain)
    resolved = {domain: lookup_domain(domain) for domain in dict.fromkeys(domains)}
    rows = [
        classify_hit(
            hit['ip'],
            tls13=bool(hit.get('tls13')),
            h2=bool(hit.get('h2')),
            domain=hit.get('domain') or '',
            wildcard_only=bool(hit.get('wildcard_only')),
            issuer=hit.get('issuer') or '',
            resolved=resolved.get(hit.get('domain') or ''),
        )
        for hit in hits
    ]
    rows.sort(key=lambda row: (0 if row['keep'] else 1, row['domain'], row['ip']))
    return rows


def _probe_all(hosts: list[str]) -> list[dict]:
    hits: list[dict] = []
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = [pool.submit(probe_address, ip) for ip in hosts]
        try:
            for future in as_completed(futures, timeout=_DEADLINE):
                hit = future.result()
                if hit:
                    hits.append(hit)
        except TimeoutError:
            for future in futures:
                future.cancel()
    return hits


def probe_address(ip: str, timeout: float = _TIMEOUT) -> dict | None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_alpn_protocols(['h2', 'http/1.1'])
    except NotImplementedError:
        return None
    try:
        sock = socket.create_connection((ip, _PORT), timeout=timeout)
    except OSError:
        return None
    try:
        sock.settimeout(timeout)
        tls = context.wrap_socket(sock, server_hostname=None)
    except (OSError, ssl.SSLError):
        sock.close()
        return None
    try:
        version = tls.version() or ''
        alpn = tls.selected_alpn_protocol() or ''
        der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None
    finally:
        tls.close()
    if not der:
        return None
    try:
        cert = x509.load_der_x509_certificate(der)
    except ValueError:
        return None
    exact, wildcards = names_from_certificate(cert)
    return {
        'ip': ip,
        'tls13': version == 'TLSv1.3',
        'h2': alpn == 'h2',
        'domain': exact[0] if exact else '',
        'wildcard_only': not exact and bool(wildcards),
        'issuer': _issuer(cert),
    }


def _issuer(cert: x509.Certificate) -> str:
    try:
        orgs = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if orgs:
            return ' | '.join(str(item.value) for item in orgs if item.value)
    except Exception:
        pass
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return str(names[0].value) if names else ''
    except Exception:
        return ''


def _lookup_uncached(domain: str) -> list[str] | None:
    def query() -> list[str]:
        infos = socket.getaddrinfo(domain, _PORT, type=socket.SOCK_STREAM)
        found: list[str] = []
        for info in infos:
            ip = str(info[4][0]).split('%')[0]
            if ip not in found:
                found.append(ip)
        return found

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(query)
        try:
            found = future.result(timeout=_DNS_TIMEOUT)
        except (OSError, TimeoutError, socket.timeout):
            return None
    return found or None
