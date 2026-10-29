from datetime import datetime, timedelta, timezone

from sqlmodel import Session, SQLModel, create_engine

from app.bootstrap import seed_if_empty
from app.mihomo import render_profile
from app.models import Client, Node, NodeInbound


def test_render_injects_node_proxy():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        seed_if_empty(session)
        node = Node(
            name='Italy',
            flag='🇮🇹',
            clash_name='Italy',
            panel_url='https://127.0.0.1:2053/',
            api_token='test',
            public_host='150.241.73.105',
            enabled=True,
        )
        session.add(node)
        session.commit()
        session.refresh(node)
        session.add(
            NodeInbound(
                node_id=node.id,
                xui_inbound_id=1,
                remark='grpc',
                port=443,
                protocol='vless',
                network='grpc',
                public_key='pubkey',
                short_id='abcd',
                fingerprint='chrome',
                server_names='gitlab.com,auth.gitlab.com',
                grpc_service_name='grpc',
                use_in_sub=True,
                use_global_sni=True,
            )
        )
        client = Client(
            name='Igor',
            slug='igor',
            uuid='11111111-1111-1111-1111-111111111111',
            sub_token='tokentoken123456',
            enable=True,
            expire_at=datetime.now(timezone.utc) + timedelta(days=10),
        )
        session.add(client)
        session.commit()
        session.refresh(client)
        yaml_text = render_profile(session, client)
        assert '150.241.73.105' in yaml_text
        assert 'tokentoken123456' in yaml_text
        assert 'IP-CIDR,150.241.73.105/32,DIRECT' in yaml_text
        assert 'proxy-providers:' in yaml_text
        assert 'geox-url:' in yaml_text
        assert 'geoip.dat' in yaml_text
        assert 'type: http' in yaml_text
        assert '# {{XUI_' not in yaml_text
        assert 'rule-providers:' in yaml_text
        assert 'category-ai@domain' in yaml_text
        assert 'YouTube' in yaml_text
        assert 'MATCH,Local' in yaml_text
