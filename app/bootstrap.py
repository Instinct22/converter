import re
from pathlib import Path

from sqlmodel import Session, select

from app.models import ConfigDoc, InboundTemplate, utcnow

DEFAULT_YAML = Path(__file__).parent / 'default_mihomo.yaml'

_FALLBACK_DIRECT = re.compile(r'\n[ \t]*proxies:\n[ \t]*- DIRECT(?=\n)')


def strip_fallback_direct(text: str) -> str:
    marker = 'name: Reality pool fallback'
    if marker not in text:
        return text
    head, rest = text.split(marker, 1)
    group, sep, tail = rest.partition('\n  - name:')
    group = _FALLBACK_DIRECT.sub('', group, count=1)
    return head + marker + group + sep + tail


def seed_if_empty(session: Session) -> None:
    profile = DEFAULT_YAML.read_text(encoding='utf-8')
    doc = session.exec(select(ConfigDoc)).first()
    if doc is None:
        session.add(ConfigDoc(yaml_text=profile, updated_at=utcnow()))
    elif (
        'category-ai@domain' not in (doc.yaml_text or '')
        or 'YouTube' not in (doc.yaml_text or '')
        or 'geox-url:' not in (doc.yaml_text or '')
        or 'XUI_PROVIDERS_BEGIN' not in (doc.yaml_text or '')
    ):
        doc.yaml_text = profile
        doc.updated_at = utcnow()
        session.add(doc)
    elif doc.yaml_text and strip_fallback_direct(doc.yaml_text) != doc.yaml_text:
        doc.yaml_text = strip_fallback_direct(doc.yaml_text)
        doc.updated_at = utcnow()
        session.add(doc)
    if session.exec(select(InboundTemplate)).first() is None:
        session.add(
            InboundTemplate(
                name='Основной порт 443 (gRPC)',
                port=443,
                protocol='vless',
                network='grpc',
                security='reality',
                dest='www.apple.com:443',
                server_names='www.apple.com, images.apple.com, www.apple.com.cn',
                grpc_service_name='grpc',
                fingerprint='chrome',
                spider_x='/',
                extra_snis='',
                use_global_sni=False,
                provider_label='apple',
            )
        )
        session.add(
            InboundTemplate(
                name='Запасной порт 8443 (xhttp)',
                port=8443,
                protocol='vless',
                network='xhttp',
                security='reality',
                dest='www.yahoo.com:443',
                server_names='www.yahoo.com,news.yahoo.com',
                xhttp_path='/',
                xhttp_mode='auto',
                fingerprint='chrome',
                extra_snis='',
                use_global_sni=False,
                enabled=False,
            )
        )
        session.add(
            InboundTemplate(
                name='Cloudflare 8443 (gRPC)',
                port=8443,
                protocol='vless',
                network='grpc',
                security='reality',
                dest='www.cloudflare.com:443',
                server_names='www.cloudflare.com',
                grpc_service_name='grpc',
                fingerprint='chrome',
                spider_x='/',
                extra_snis='',
                use_global_sni=False,
                provider_label='cloudflare',
                use_in_sub=True,
            )
        )
    session.commit()
