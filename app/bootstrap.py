import re
from pathlib import Path

from sqlmodel import Session, select

from app.models import ConfigDoc, InboundTemplate, utcnow

DEFAULT_YAML = Path(__file__).parent / 'default_mihomo.yaml'

_FALLBACK_DIRECT = re.compile(r'\n[ \t]*proxies:\n[ \t]*- DIRECT(?=\n)')
_CUSTOM_MARKER = '# Custom overrides'
_CUSTOM_RULES = (
    '  - PROCESS-NAME,ru.oneme.app,Custom local',
    '  - DOMAIN-SUFFIX,max.ru,Custom local',
    '  - DOMAIN-SUFFIX,oneme.ru,Custom local',
)


def ensure_custom_overrides(text: str) -> str:
    """Правила MAX сразу под комментарием, не затирая остальной шаблон."""
    if not text or _CUSTOM_MARKER not in text:
        return text
    missing = [rule for rule in _CUSTOM_RULES if rule not in text]
    if not missing:
        return text
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    inserted = False
    for line in lines:
        out.append(line)
        if inserted or _CUSTOM_MARKER not in line:
            continue
        newline = '\r\n' if line.endswith('\r\n') else '\n'
        out.extend(rule + newline for rule in missing)
        inserted = True
    return ''.join(out)


_PROBE_LINE = re.compile(
    r'\n[ \t]*(?:'
    r'url: https://cp\.cloudflare\.com/generate_204|'
    r'interval: 30|'
    r'lazy: false|'
    r'expected-status: [\'"]204[\'"]'
    r')(?=\n)'
)


def strip_probe_schedule(text: str) -> str:
    """У Reality pool fallback нет таймера опроса.

    Интервал 30 секунд и URL проверки заставляют чужой Mihomo обойти каждый
    прокси. Свой клиент этот блок не запускает, поэтому в шаблоне его нет.
    """
    marker = 'name: Reality pool fallback'
    if marker not in text:
        return text
    head, rest = text.split(marker, 1)
    group, sep, tail = rest.partition('\n  - name:')
    return head + marker + _PROBE_LINE.sub('', group) + sep + tail


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
    if doc is not None and doc.yaml_text:
        updated = strip_probe_schedule(doc.yaml_text)
        updated = ensure_custom_overrides(updated)
        if updated != doc.yaml_text:
            doc.yaml_text = updated
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
                name='Yahoo 8443 (gRPC)',
                port=8443,
                protocol='vless',
                network='grpc',
                security='reality',
                dest='www.yahoo.com:443',
                server_names='www.yahoo.com, ymail.com, s.yimg.com',
                grpc_service_name='grpc',
                fingerprint='chrome',
                spider_x='/',
                extra_snis='',
                use_global_sni=False,
                provider_label='yahoo',
                use_in_sub=True,
            )
        )
    session.commit()
