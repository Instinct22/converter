from sqlmodel import Session, SQLModel, create_engine

from app.models import Node
from app.ssh_access import (
    AUTH_KEY,
    AUTH_PASSWORD,
    adopt_node,
    fingerprint,
    install_pubkey_script,
    key_lockdown_script,
    lockdown_script,
    public_key_line,
    resolved_auth,
    valid_public_key,
)
from app.xui_install import prepare_install


def test_fleet_key_is_ed25519_and_has_a_fingerprint():
    line = public_key_line()
    assert valid_public_key(line)
    assert line.startswith('ssh-ed25519 ')
    assert line.endswith('master@fleet')
    assert fingerprint().startswith('SHA256:')


def test_pubkey_script_appends_once_and_lockdown_waits_for_sshd():
    script = install_pubkey_script('ssh-ed25519 AAAA master@fleet')
    assert 'grep -qxF' in script
    assert 'MASTER_PUB_OK' in script
    assert 'PasswordAuthentication no' not in script
    locked = lockdown_script(22, '5.180.174.204')
    assert 'PasswordAuthentication no' in locked
    assert 'PASSWORD_AUTH' in locked
    assert 'sshd -t' in locked
    assert 'ufw insert 1 allow from 5.180.174.204' in locked
    assert locked.index('cat /run/master-ssh-auth') < locked.index('systemctl reload')
    assert 'echo MASTER_KEY_OK' in key_lockdown_script()


def test_resolved_auth_treats_a_stored_password_as_password_only():
    node = Node(name='NL', panel_url='https://x', ssh_password='secret')
    assert resolved_auth(node) == AUTH_PASSWORD
    node.ssh_auth = AUTH_KEY
    node.ssh_password = ''
    assert resolved_auth(node) == AUTH_KEY


def test_adopt_forgets_the_password_only_after_the_key_logs_in():
    node = Node(
        name='NL',
        panel_url='https://x',
        public_host='1.2.3.4',
        ssh_password='secret',
        ssh_auth=AUTH_PASSWORD,
    )
    seen = []

    def runner(mode, command):
        seen.append(mode)
        if mode == 'key' and seen.count('key') == 1:
            return 1, '', 'denied'
        if mode == 'password':
            assert 'authorized_keys' in command
            return 0, 'MASTER_PUB_OK\n', ''
        assert 'MASTER_KEY_OK' in command
        assert 'PasswordAuthentication no' in command
        return 255, 'MASTER_KEY_OK\nPASSWORD_AUTH no\n', 'connection reset'

    result = adopt_node(node, runner=runner)
    assert result.ok is True
    assert node.ssh_auth == AUTH_KEY
    assert node.ssh_password == ''
    assert seen.count('password') == 1
    assert seen.count('key') == 2


def test_adopt_keeps_the_password_when_the_key_never_logs_in():
    node = Node(
        name='NL',
        panel_url='https://x',
        public_host='1.2.3.4',
        ssh_password='secret',
        ssh_auth=AUTH_PASSWORD,
    )

    def runner(mode, command):
        if mode == 'password':
            return 0, 'MASTER_PUB_OK\n', ''
        return 1, '', 'no'

    result = adopt_node(node, runner=runner)
    assert result.ok is False
    assert node.ssh_auth == AUTH_PASSWORD
    assert node.ssh_password == 'secret'
    assert 'пароль оставлен' in result.logs[0]


def test_prepare_install_allows_an_empty_password_when_the_key_is_already_there(known_install_hosts):
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        node = prepare_install(
            session,
            flag='NL',
            name='Netherlands-01',
            clash_name='',
            host='95.85.120.14',
            ssh_user='root',
            ssh_password='',
            ssh_port=22,
        )
        assert node.ssh_password == ''
        assert node.ssh_auth == AUTH_KEY
