from sqlmodel import Session, SQLModel, create_engine, select

from app.models import InboundTemplate, Node, NodeInbound
from app.provision import set_node_template_ids, sync_node


class FakeXui:
    def __init__(self, _node):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def panel_settings(self):
        return {}

    def inbounds(self):
        return [
            {
                'id': 99,
                'remark': '443',
                'port': 443,
                'protocol': 'vless',
                'streamSettings': '{"network":"grpc","security":"reality","realitySettings":{"serverNames":["new.from.panel"],"publicKey":"pk","shortIds":["ab"]}}',
                'settings': '{}',
            }
        ]


def test_sync_uses_template_sni_when_assigned(monkeypatch):
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = Node(
            name='IT',
            panel_url='https://127.0.0.1:2053/x',
            api_token='t',
            public_host='150.241.73.105',
        )
        tpl = InboundTemplate(
            name='443 gitlab',
            port=443,
            server_names='www.yahoo.com,ymail.com',
        )
        session.add(node)
        session.add(tpl)
        session.commit()
        session.refresh(node)
        session.refresh(tpl)
        set_node_template_ids(session, node.id or 0, [tpl.id or 0])

        monkeypatch.setattr('app.provision.XuiClient', FakeXui)
        monkeypatch.setattr('app.provision.apply_sub_settings', lambda *a, **k: None)
        monkeypatch.setattr('app.provision.refresh_clash_sub_path', lambda *a, **k: None)

        sync_node(session, node)
        saved = session.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).first()
        assert saved.server_names == 'www.yahoo.com,ymail.com'
