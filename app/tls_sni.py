from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


def parse_dest(dest: str) -> tuple[str, int]:
    value = (dest or '').strip()
    if not value:
        raise ValueError('укажите dest, например gitlab.com:443')
    if '://' not in value:
        value = 'https://' + value
    parsed = urlparse(value)
    host = parsed.hostname
    if not host:
        raise ValueError('не удалось разобрать хост dest')
    port = parsed.port or 443
    return host, port


def names_from_certificate(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    exact: list[str] = []
    wildcards: list[str] = []

    def add(name: str) -> None:
        item = (name or '').strip().lower().rstrip('.')
        if not item:
            return
        if item.startswith('*.'):
            if item not in wildcards:
                wildcards.append(item)
            return
        if item not in exact:
            exact.append(item)

    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for attr in cn:
            add(attr.value)
    except Exception:
        pass
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for dns in ext.value.get_values_for_type(x509.DNSName):
            add(dns)
    except x509.ExtensionNotFound:
        pass
    return exact, wildcards


def fetch_dest_sni(dest: str, timeout: float = 8.0) -> dict:
    host, port = parse_dest(dest)
    der = _peer_cert_der(host, port, timeout)
    cert = x509.load_der_x509_certificate(der)
    names, wildcards = names_from_certificate(cert)
    host_l = host.lower()
    if host_l not in names:
        names = [host_l, *names]
    return {
        'dest': f'{host}:{port}',
        'host': host,
        'port': port,
        'names': names,
        'wildcards': wildcards,
        'issuer': _issuer_cn(cert),
    }


def _issuer_cn(cert: x509.Certificate) -> str:
    try:
        attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ''
    except Exception:
        return ''


def _peer_cert_der(host: str, port: int, timeout: float) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        raise RuntimeError(f'не достучались до {host}:{port}: {exc}') from exc
    if not der:
        raise RuntimeError(f'{host}:{port} не отдал TLS-сертификат')
    return der
