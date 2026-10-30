from sqlmodel import Session, SQLModel, create_engine, select

from app.models import InboundTemplate, Node, NodeInbound
from app.provision import set_node_template_ids, sync_node, templates_for_node


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
                'remark': '8443',
                'port': 8443,
                'protocol': 'vless',
                'streamSettings': '{"network":"grpc","security":"reality","realitySettings":{"serverNames":["from.panel"],"publicKey":"pk","shortIds":["ab"]}}',
                'settings': '{}',
            }
        ]


def test_sync_applies_assigned_template_sub_fields(monkeypatch):
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
            name='Yahoo 8443',
            port=8443,
            server_names='www.yahoo.com,ymail.com',
            extra_snis='s.yimg.com',
            provider_label='yahoo',
            use_in_sub=True,
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
        row = session.exec(select(NodeInbound).where(NodeInbound.node_id == node.id)).first()
        assert row is not None
        assert row.server_names == 'www.yahoo.com,ymail.com'
        assert row.provider_label == 'yahoo'
        assert row.use_in_sub is True


def test_templates_for_node_respects_assignment():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = Node(name='N', panel_url='https://x/y', api_token='t')
        a = InboundTemplate(name='443', port=443, enabled=True)
        b = InboundTemplate(name='8443', port=8443, enabled=True)
        session.add(node)
        session.add(a)
        session.add(b)
        session.commit()
        session.refresh(node)
        session.refresh(a)
        set_node_template_ids(session, node.id or 0, [a.id or 0])
        names = [t.name for t in templates_for_node(session, node)]
        assert names == ['443']


def test_reconcile_keeps_existing_port_creates_missing_deletes_extra(monkeypatch):
    from app.provision import reconcile_node_templates

    state = {
        'rows': [
            {'id': 10, 'remark': '8443', 'port': 8443, 'protocol': 'vless', 'settings': '{}', 'streamSettings': '{}'},
            {'id': 11, 'remark': 'junk', 'port': 49579, 'protocol': 'vless', 'settings': '{}', 'streamSettings': '{}'},
        ],
        'added': [],
        'deleted': [],
    }

    class FakeXui:
        def __init__(self, _node, timeout=60.0):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def inbounds(self):
            return list(state['rows'])

        def del_inbound(self, inbound_id):
            state['deleted'].append(inbound_id)
            state['rows'] = [row for row in state['rows'] if row['id'] != inbound_id]
            return {'success': True}

        def add_inbound(self, spec):
            state['added'].append(spec['port'])
            state['rows'].append(
                {
                    'id': 12,
                    'remark': spec['remark'],
                    'port': spec['port'],
                    'protocol': spec['protocol'],
                    'settings': spec['settings'],
                    'streamSettings': spec['streamSettings'],
                }
            )
            return {'success': True}

        def panel_settings(self):
            return {}

    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = Node(name='IT', panel_url='https://127.0.0.1:2053/x', api_token='t', public_host='1.1.1.1')
        apple = InboundTemplate(name='443 Apple', port=443, enabled=True, server_names='www.apple.com')
        yahoo = InboundTemplate(name='8443 Yahoo', port=8443, enabled=True, server_names='www.yahoo.com')
        session.add(node)
        session.add(apple)
        session.add(yahoo)
        session.commit()
        session.refresh(node)
        session.refresh(apple)
        session.refresh(yahoo)
        kept = NodeInbound(
            node_id=node.id or 0,
            xui_inbound_id=10,
            port=8443,
            use_in_sub=False,
            server_names='keep.me',
            snis_locked=True,
        )
        session.add(kept)
        session.commit()
        monkeypatch.setattr('app.provision.XuiClient', FakeXui)
        monkeypatch.setattr('app.provision.apply_sub_settings', lambda *a, **k: None)
        monkeypatch.setattr('app.provision.refresh_clash_sub_path', lambda *a, **k: None)
        logs = reconcile_node_templates(session, node, [apple.id or 0, yahoo.id or 0])
        assert state['deleted'] == [11]
        assert state['added'] == [443]
        assert any('порт 8443 уже есть' in line for line in logs)
        assert any('49579' in line and 'удалён' in line for line in logs)
        assert any('443' in line and 'создан' in line for line in logs)
        kept_row = session.exec(
            select(NodeInbound).where(NodeInbound.xui_inbound_id == 10)
        ).one()
        assert kept_row.use_in_sub is False
        assert kept_row.server_names == 'keep.me'
        created_row = session.exec(
            select(NodeInbound).where(NodeInbound.port == 443)
        ).one()
        assert created_row.use_in_sub is True
        assert created_row.server_names == 'www.apple.com'
