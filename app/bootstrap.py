import hashlib
from pathlib import Path

from sqlmodel import Session, select

from app.models import ConfigDoc, InboundTemplate, utcnow

DEFAULT_YAML = Path(__file__).parent / 'default_mihomo.yaml'

# Exact unmodified profiles shipped in previous releases (LF-normalized).
_PREVIOUS_DEFAULTS = {
    '1d414a28b85612fb0710a8327f413aa0626d4bf9a4cc796266581afe6a6fdf48',  # e39b519
    '460e61cabeef5c53f35aad4b11f067ee7eb02687067eab1b6d8cff57dbf4b42c',  # 2bae81b
    'f6deabadfb72a37b30bbaa56e21ff25abe77ded6055e68201759415c900c773f',  # 130042d
    '0dc74b55ebfbf05d788965cf4917355d92a6db3aca13fb6858de61dbc1c601e1',  # 65376da
    '5c80d54694af32967953130997ed05d0ee3f08ab8479bff10397680c1ed95308',  # 3c11781
    'c1b16a586836cf38574803228431451ef74a3c04b9e72f48927f073b77c5ea78',  # d0b198c
}


def seed_if_empty(session: Session) -> None:
    profile = DEFAULT_YAML.read_text(encoding='utf-8')
    doc = session.exec(select(ConfigDoc)).first()
    if doc is None:
        session.add(ConfigDoc(yaml_text=profile, updated_at=utcnow()))
    elif hashlib.sha256(doc.yaml_text.replace('\r\n', '\n').encode()).hexdigest() in _PREVIOUS_DEFAULTS:
        doc.yaml_text = profile
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
