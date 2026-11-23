from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select

from app import exporters
from app.database import get_session
from app.main import app
from app.models import (Client, ClientPlacement, InboundTemplate, MasterOperation, Node,
                        NodeInbound, NodePingHour, NodeTemplateAssignment, utcnow)
from app.node_updates import check_updates
from app.overview import aggregate_client_usage, client_rows_from_inbounds, remember_last_online
from app.provision import disable_expired
from app.settings import settings
from app.xui import XuiError


def test_delete_with_ping_history_and_audit_ui(tmp_path):
    engine = create_engine('sqlite:///' + (tmp_path / 'master.db').as_posix())

    @event.listens_for(engine, 'connect')
    def enable_foreign_keys(conn, _):
        conn.execute('PRAGMA foreign_keys=ON')

    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = Node(name='Italy-01', panel_url='https://invalid/secret-path', api_token='hidden-test-token')
        other = Node(name='Italy-02', panel_url='')
        client = Client(name='Demo', slug='demo', uuid='uuid', sub_token='hidden-sub-token')
        template = InboundTemplate(name='test', port=443)
        session.add_all([node, other, client, template])
        session.commit()
        inbound = NodeInbound(node_id=node.id, xui_inbound_id=1)
        session.add(inbound)
        session.commit()
        node_id = node.id
        session.add_all([ClientPlacement(node_id=node.id, inbound_id=inbound.id, client_id=client.id),
                         NodeTemplateAssignment(node_id=node.id, template_id=template.id),
                         NodePingHour(node_id=node.id, hour=utcnow()), NodePingHour(node_id=other.id, hour=utcnow())])
        session.commit()

    def sessions():
        with Session(engine) as local:
            yield local

    app.dependency_overrides[get_session] = sessions
    try:
        web = TestClient(app)
        assert web.get('/logs?fragment=true', follow_redirects=False).status_code == 302
        web.post('/login', data={'username': settings.admin_username, 'password': settings.admin_password})
        dashboard = web.get('/').text
        assert 'data-agent-install' in dashboard and 'Был в сети' in dashboard
        assert 'Поставить агенты' not in dashboard
        response = web.delete(f'/api/nodes/{node_id}')
        assert response.json() == {'ok': True}
        assert web.delete(f'/api/nodes/{node_id}').status_code == 404
        logs = web.get('/logs', params={'q': 'Italy-01', 'state': 'ok', 'source': 'admin'})
        assert logs.status_code == 200 and 'Italy-01' in logs.text and 'Удаление сервера' in logs.text
        assert 'hidden-test-token' not in logs.text and 'secret-path' not in logs.text
        assert 'Успешно' in logs.text and 'UTC+3' in logs.text
        assert 'HTTP 404' in web.get('/logs?fragment=true&state=error').text
        with Session(engine) as session:
            assert session.get(Node, node_id) is None
            assert len(session.exec(select(NodePingHour)).all()) == 1
            assert len(session.exec(select(Client)).all()) == 1
            assert session.exec(select(ClientPlacement)).first() is None
            assert session.exec(select(NodeTemplateAssignment)).first() is None
            assert session.exec(select(MasterOperation).where(MasterOperation.state == 'running')).first() is None
    finally:
        app.dependency_overrides.pop(get_session)
        engine.dispose()


def test_sqlite_expiry_does_not_abort_fleet_poll():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        for name, days in [('active', 1), ('expired', -1)]:
            session.add(Client(name=name, slug=name, uuid=name, sub_token=name,
                               expire_at=utcnow() + timedelta(days=days)))
        session.commit()
        assert disable_expired(session) == 1
        assert [c.name for c in session.exec(select(Client).where(Client.enable.is_(True)))] == ['active']


def test_xray_discovery_survives_panel_check_failure(monkeypatch):
    node = Node(name='new', panel_url='', xray_version='1.0')
    class Panel:
        def __init__(self, node): pass
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def server_status(self): return {'xrayVersion': '1.0'}
        def get_panel_update_info(self): raise XuiError('HTTP 403')
        def get_xray_versions(self): return ['v1.1']
    monkeypatch.setattr('app.node_updates.XuiClient', Panel)
    info = check_updates(node)
    assert node.panel_check_error == 'HTTP 403' and info['xray_differs']
    monkeypatch.setattr(Panel, 'get_panel_update_info',
                        lambda self: {'currentVersion': '2.1', 'latestVersion': '2.2'})
    assert check_updates(node)['panel_differs']
    assert node.xui_version == '2.1' and not node.panel_check_error


def test_last_seen_survives_missing_panels_and_ignores_other_clients():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        client = Client(name='Jane', slug='jane', uuid='id', sub_token='token')
        session.add(client)
        session.commit()
        nodes = [Node(id=i, name=str(i), panel_url='') for i in (1, 2)]
        rows = client_rows_from_inbounds([{'clientStats': [
            {'email': 'jane', 'lastOnline': 1700000000000},
            {'email': 'jane-doe', 'lastOnline': 1800000000000}]}])
        usage = aggregate_client_usage(client, nodes, {
            1: {'client_rows': rows}, 2: {'last_online': {'jane-443-1': 1700000020, 'jane-doe': 1800000000}}})
        assert usage['last_online'] == 1700000020
        remember_last_online(session, client, usage['last_online'])
        session.commit()
        assert aggregate_client_usage(client, nodes, {})['last_online'] == 1700000020


def test_install_agent_queues_only_requested_node(monkeypatch):
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    captured = []
    monkeypatch.setattr(exporters, 'grafana_target', lambda session: ('receiver', 'credential'))
    monkeypatch.setattr(exporters.threading.Thread, 'start', lambda thread: captured.append(thread))
    with Session(engine) as session:
        first, second = [Node(name=name, panel_url='') for name in ['first', 'second']]
        session.add_all([first, second])
        session.commit()
        assert exporters.start_exporters(session, first.id) == 1
        assert first.exporter_state == 'installing' and second.exporter_state == ''
        with pytest.raises(ValueError):
            exporters.start_exporters(session, first.id)
        assert len(captured) == 1
