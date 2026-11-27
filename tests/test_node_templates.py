from unittest.mock import MagicMock

import pytest
from sqlmodel import Session, SQLModel, create_engine, select

from app.models import InboundTemplate, Node, NodeInbound
from app.provision import set_node_template_ids, sync_node, templates_for_node
from app.routers import api


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


@pytest.mark.parametrize('install', [True, False], ids=['clean-vps', 'existing-panel'])
def test_new_node_starts_without_assigned_templates(install, known_install_hosts, monkeypatch):
    from app.provision import ensure_default_node_templates, node_template_ids

    panel = MagicMock()
    panel.__enter__.return_value.inbounds.return_value = []
    panel.__enter__.return_value.panel_settings.return_value = {}
    monkeypatch.setattr(api, 'XuiClient', lambda node: panel)
    monkeypatch.setattr('app.provision.XuiClient', lambda node: panel)
    monkeypatch.setattr(api, 'check_updates', lambda node: None)
    monkeypatch.setattr(api, 'start_install', lambda node_id: None)
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([InboundTemplate(name='Apple', port=443), InboundTemplate(name='Yahoo', port=8443)])
        session.commit()
        result = api.create_node(api.NodeIn(name='New', install=install, host='203.0.113.10',
                                            panel_url='https://203.0.113.10', api_token='test'), session)
        assert result['node']['template_ids'] == []
        node_id = result['node']['id']
    with Session(engine) as session:
        ensure_default_node_templates(session)
        assert node_template_ids(session, node_id) == []
    engine.dispose()


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

        def get_inbound(self, inbound_id):
            return {
                'id': inbound_id,
                'streamSettings': '{"network":"grpc","security":"reality","realitySettings":{"serverNames":["keep.me"],"privateKey":"keep"}}',
                'settings': '{}',
                'sniffing': '{}',
            }

        def update_inbound(self, inbound_id, spec):
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
        assert kept_row.server_names == 'www.yahoo.com'
        created_row = session.exec(
            select(NodeInbound).where(NodeInbound.port == 443)
        ).one()
        assert created_row.use_in_sub is True
        assert created_row.server_names == 'www.apple.com'


def test_apply_rejects_two_templates_on_one_port(monkeypatch):
    from app.provision import apply_node_templates

    class FakeXui:
        def __init__(self, *args, **kwargs):
            raise AssertionError('панель не должна вызываться')

    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = Node(name='EE', panel_url='https://127.0.0.1:2053/x', api_token='t')
        yahoo = InboundTemplate(name='8443 Yahoo', port=8443, enabled=True)
        other = InboundTemplate(name='test2222', port=8443, enabled=True)
        session.add(node)
        session.add(yahoo)
        session.add(other)
        session.commit()
        session.refresh(node)
        session.refresh(yahoo)
        session.refresh(other)
        monkeypatch.setattr('app.provision.XuiClient', FakeXui)
        logs = apply_node_templates(session, node, [yahoo.id or 0, other.id or 0])
        assert any('8443' in line and 'не навесился' in line for line in logs)
        assert any('8443 Yahoo' in line and 'test2222' in line for line in logs)


def test_apply_rewrites_snis_from_assigned_template(monkeypatch):
    import json

    from app.provision import apply_node_templates, set_node_template_ids

    pushed: dict[str, object] = {}

    class FakeXui:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_inbound(self, inbound_id):
            return {
                'id': inbound_id,
                'streamSettings': json.dumps({
                    'network': 'grpc',
                    'security': 'reality',
                    'realitySettings': {'serverNames': ['www.yahoo.com'], 'privateKey': 'keep-key'},
                }),
                'settings': '{}',
                'sniffing': '{}',
            }

        def update_inbound(self, inbound_id, spec):
            stream = json.loads(spec['streamSettings'])
            pushed['names'] = stream['realitySettings']['serverNames']
            pushed['private'] = stream['realitySettings']['privateKey']
            return {'success': True}

    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = Node(name='FI', panel_url='https://127.0.0.1:2053/x', api_token='t')
        samsung = InboundTemplate(
            name='test2222',
            port=8443,
            enabled=True,
            server_names='www.samsung.com, images.samsung.com',
        )
        session.add(node)
        session.add(samsung)
        session.commit()
        session.refresh(node)
        session.refresh(samsung)
        inbound = NodeInbound(
            node_id=node.id or 0,
            xui_inbound_id=7,
            port=8443,
            remark='test2222',
            server_names='www.yahoo.com, ymail.com, s.yimg.com',
            provider_label='yahoo',
            snis_locked=True,
            use_in_sub=True,
        )
        session.add(inbound)
        session.commit()
        set_node_template_ids(session, node.id or 0, [samsung.id or 0])
        monkeypatch.setattr('app.provision.XuiClient', FakeXui)
        logs = apply_node_templates(session, node, [samsung.id or 0])
        session.refresh(inbound)
        assert inbound.server_names == 'www.samsung.com, images.samsung.com'
        assert inbound.use_in_sub is True
        assert pushed['names'] == ['www.samsung.com', 'images.samsung.com']
        assert pushed['private'] == 'keep-key'
        assert any('SNI' in line and '2 имён' in line for line in logs)


def test_sync_pushes_renamed_remark(monkeypatch):
    import json

    from app.provision import sync_template_fields

    pushed: dict[str, object] = {}

    class FakeXui:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def get_inbound(self, inbound_id):
            return {
                'id': inbound_id,
                'remark': '443 Apple',
                'streamSettings': json.dumps({
                    'network': 'grpc',
                    'security': 'reality',
                    'realitySettings': {'serverNames': ['www.wikipedia.org'], 'privateKey': 'keep-key'},
                }),
                'settings': '{}',
                'sniffing': '{}',
            }

        def update_inbound(self, inbound_id, spec):
            pushed['remark'] = spec.get('remark')
            pushed['private'] = json.loads(spec['streamSettings'])['realitySettings']['privateKey']
            return {'success': True}

    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = Node(name='IT', panel_url='https://127.0.0.1:2053/x', api_token='t')
        wiki = InboundTemplate(
            name='2083 Wikipedia',
            port=2083,
            enabled=True,
            server_names='www.wikipedia.org',
            provider_label='wikipedia',
            use_in_sub=True,
        )
        session.add(node)
        session.add(wiki)
        session.commit()
        session.refresh(node)
        session.refresh(wiki)
        inbound = NodeInbound(
            node_id=node.id or 0,
            xui_inbound_id=4,
            port=2083,
            remark='443 Apple',
            server_names='www.wikipedia.org',
            provider_label='wikipedia',
            snis_locked=True,
            use_in_sub=True,
        )
        session.add(inbound)
        session.commit()
        monkeypatch.setattr('app.provision.XuiClient', FakeXui)
        logs = sync_template_fields(session, node, [wiki])
        session.refresh(inbound)
        assert inbound.remark == '2083 Wikipedia'
        assert pushed['remark'] == '2083 Wikipedia'
        assert pushed['private'] == 'keep-key'
        assert any('имя входа' in line for line in logs)
