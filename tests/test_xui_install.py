from sqlmodel import Session, SQLModel, create_engine

from app.firewall import wanted_ports
from app.models import Node
from app.xui_install import apply_install_result, prepare_install, remote_script


def _memory():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def test_install_script_leaves_firewall_and_fail2ban_to_master():
    script = remote_script(
        username='user',
        password='pass',
        web_base='base',
        port=25001,
        server_ip='95.85.120.14',
        ssl_mode='ip',
    )
    assert 'на сервере уже стоит x-ui' in script
    assert 'ufw' not in script
    assert 'fail2ban' not in script
    node = Node(
        name='NL',
        panel_url='https://95.85.120.14:25001/secret',
        api_token='t',
        ssh_port=22,
        sub_port=2096,
    )
    assert wanted_ports(node, set()) == {22, 80, 25001}
    assert 443 not in wanted_ports(node, set())
    assert 2096 not in wanted_ports(node, set())
    assert wanted_ports(node, {443}) == {22, 80, 443, 25001}


def test_prepare_install_rejects_a_bad_address_and_a_taken_ip():
    with _memory() as session:
        try:
            prepare_install(
                session,
                flag='NL',
                name='Netherlands-01',
                clash_name='',
                host='999.1.1.1',
                ssh_user='root',
                ssh_password='secret',
                ssh_port=22,
            )
        except ValueError as exc:
            assert 'IPv4' in str(exc)
        else:
            raise AssertionError('bad address was accepted')
        node = prepare_install(
            session,
            flag='NL',
            name='Netherlands-01',
            clash_name='',
            host='95.85.120.14',
            ssh_user='root',
            ssh_password='secret',
            ssh_port=22,
        )
        assert node.install_state == 'installing'
        assert node.panel_url == ''
        assert node.enabled is False
        assert node.ssh_password == 'secret'
        try:
            prepare_install(
                session,
                flag='NL',
                name='Other',
                clash_name='',
                host='95.85.120.14',
                ssh_user='root',
                ssh_password='secret',
                ssh_port=22,
            )
        except ValueError as exc:
            assert 'Netherlands-01' in str(exc)
        else:
            raise AssertionError('duplicate ip was accepted')


def test_finished_install_keeps_the_token_and_shows_the_password_once(monkeypatch):
    with _memory() as session:
        node = prepare_install(
            session,
            flag='NL',
            name='Netherlands-01',
            clash_name='Netherlands-01',
            host='95.85.120.14',
            ssh_user='root',
            ssh_password='secret',
            ssh_port=22,
        )
        def runner(host, user, script, key, password, *, port=22):
            assert host == '95.85.120.14'
            assert password == 'secret'
            assert port == 22
            assert 'XUI_SSL_MODE=ip' in script
            assert 'ufw' not in script
            return 0, '\n'.join([
                'installer noise',
                'MASTER_URL=https://95.85.120.14:23456/abc',
                'MASTER_USER=paneluser',
                'MASTER_PASS=panelpass',
                'MASTER_TOKEN=secret-token',
            ])

        def firewall(current, ports, db):
            assert current.panel_url == 'https://95.85.120.14:23456/abc'
            assert current.api_token == 'secret-token'
            assert ports == set()
            return ['Netherlands-01: файрвол — 22, 80, 2096, 23456']

        monkeypatch.setattr('app.provision.disable_node_subscription', lambda node: 'ok')
        monkeypatch.setattr('app.firewall.sync_node_firewall', firewall)
        apply_install_result(session, node.id, runner=runner)
        session.refresh(node)
        assert node.api_token == 'secret-token'
        from app.routers.api import take_install_credentials
        import json
        import pytest
        from fastapi import HTTPException

        assert 'panelpass' not in node.install_log
        handoff = take_install_credentials(node.id, session)
        assert json.loads(handoff.body)['password'] == 'panelpass'
        assert handoff.headers['cache-control'] == 'no-store'
        with pytest.raises(HTTPException) as error:
            take_install_credentials(node.id, session)
        assert error.value.status_code == 404
        assert 'secret-token' not in node.install_log
        assert 'файрвол' in node.install_log
        assert node.enabled is True


def test_existing_xui_stops_the_install_without_saving_a_token():
    with _memory() as session:
        node = prepare_install(
            session,
            flag='NL',
            name='Netherlands-01',
            clash_name='',
            host='95.85.120.14',
            ssh_user='root',
            ssh_password='secret',
            ssh_port=22,
        )

        def runner(host, user, script, key, password, *, port=22):
            assert 'XUI_SSL_MODE=ip' in script
            assert 'ufw' not in script
            assert 'fail2ban' not in script
            return 2, 'MASTER_ERROR=на сервере уже стоит x-ui, повторная установка сменит пароль. Остановился.\nMASTER_TOKEN=should-not-stick\n'

        apply_install_result(session, node.id, runner=runner)
        session.refresh(node)
        assert node.install_state == 'failed'
        assert node.api_token == ''
        assert 'уже стоит x-ui' in node.install_log
        assert 'should-not-stick' not in node.install_log
