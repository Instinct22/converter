import socket
import threading

import paramiko
import pytest
from fastapi import HTTPException
from sqlmodel import Session, SQLModel, create_engine, select

from app import preflight, ssh_access
from app.models import Node
from app.routers import api


@pytest.fixture
def enrollment(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_access, 'KEY_DIR', tmp_path)
    monkeypatch.setattr(ssh_access.Path, 'home', lambda: tmp_path)
    key = paramiko.RSAKey.generate(1024)
    monkeypatch.setattr(ssh_access, '_read_server_key', lambda host, port: key)
    started = []
    monkeypatch.setattr(api, 'start_install', started.append)
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session, key, started
    engine.dispose()


def test_first_contact_requires_the_displayed_key_before_queueing(enrollment, monkeypatch):
    session, key, started = enrollment
    body = api.NodeIn(name='Test', install=True, host='192.0.2.1', ssh_port=2222, ssh_password='test-pass')
    with pytest.raises(HTTPException) as first:
        api.create_node(body, session)
    assert first.value.status_code == 409
    assert first.value.detail == dict(code='confirm_ssh_host_key', address='[192.0.2.1]:2222',
                                     algorithm=key.get_name(), fingerprint=key.fingerprint)
    assert not session.exec(select(Node)).all()
    assert not started
    body.ssh_fingerprint = key.fingerprint
    other = paramiko.RSAKey.generate(1024)
    monkeypatch.setattr(ssh_access, '_read_server_key', lambda host, port: other)
    with pytest.raises(HTTPException, match='изменился') as changed:
        api.create_node(body, session)
    assert changed.value.status_code == 400
    assert not started
    assert not session.exec(select(Node)).all()
    monkeypatch.setattr(ssh_access, '_read_server_key', lambda host, port: key)
    result = api.create_node(body, session)
    assert started == [result['node']['id']]
    with ssh_access.trusted_ssh_client(body.host, 2222) as client:
        assert client.get_host_keys().check('[192.0.2.1]:2222', key)
        assert not client.get_host_keys().check('[192.0.2.1]:2222', other)
    with ssh_access.trusted_ssh_client(body.host, 22) as client:
        assert not client.get_host_keys().lookup(body.host)
    with pytest.raises(ssh_access.HostIdentityError, match='сохранённым'):
        ssh_access.verify_install_host(body.host, 2222, other.fingerprint)


def test_retry_uses_failed_card_and_keeps_preflight_strict_for_managed_nodes(enrollment):
    session, key, started = enrollment
    node = Node(name='Poland-01', panel_url='', enabled=False, public_host='192.0.2.2',
                install_state='failed', install_kind='xui', ssh_password='test-pass',
                install_log='Не удалось зайти по SSH: Для 192.0.2.2 нет проверенного ключа в known_hosts')
    session.add(node)
    session.commit()
    assert preflight.check_nodes(session) == []
    with pytest.raises(HTTPException) as first:
        api.retry_install(node.id, api.InstallTrust(), session)
    assert first.value.detail['fingerprint'] == key.fingerprint
    assert node.install_state == 'failed' and not started
    api.retry_install(node.id, api.InstallTrust(ssh_fingerprint=key.fingerprint), session)
    assert session.exec(select(Node)).one().id == node.id
    assert node.ssh_password == 'test-pass'
    assert node.install_state == 'installing'
    with pytest.raises(HTTPException) as duplicate:
        api.retry_install(node.id, api.InstallTrust(), session)
    assert duplicate.value.status_code == 409 and started == [node.id]
    node.install_state = 'done'
    assert preflight.check_nodes(session) == []
    node.public_host = '192.0.2.3'
    assert 'known_hosts' in preflight.check_nodes(session)[0]


def test_probe_reads_key_without_authenticating(monkeypatch):
    key = paramiko.RSAKey.generate(1024)
    local, remote = socket.socketpair()
    monkeypatch.setattr(socket, 'create_connection', lambda *args, **kwargs: local)
    auth_attempts = []

    class Server(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            auth_attempts.append(username)
            return 'password'

    with paramiko.Transport(remote) as server:
        server.add_server_key(key)
        server.start_server(event=threading.Event(), server=Server())
        assert ssh_access._read_server_key('192.0.2.4', 2222) == key
    assert not auth_attempts
