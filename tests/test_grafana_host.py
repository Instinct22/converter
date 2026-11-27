import json

import yaml
from fastapi import HTTPException
from sqlmodel import Session, SQLModel, create_engine

from app.grafana_host import (
    GrafanaHost,
    caddy_text,
    compose_text,
    datasource_text,
    apply_grafana_install,
    new_admin_password,
    new_write_token,
    parse_markers,
    redact,
    remote_script,
    update_env_file,
    write_url,
)


def sample(**kwargs) -> GrafanaHost:
    data = dict(
        host='203.0.113.10',
        domain='',
        admin_user='admin',
        admin_password='Aa1-' + ('b' * 12),
        write_token='a' * 32,
        ssh_port=22,
        master_ip='198.51.100.10',
        acme_email='admin@aegis-gate.ru',
    )
    data.update(kwargs)
    return GrafanaHost(**data)


def test_compose_publishes_only_caddy():
    loaded = yaml.safe_load(compose_text(sample()))
    assert 'ports' not in loaded['services']['grafana']
    assert 'ports' not in loaded['services']['victoriametrics']
    assert loaded['services']['caddy']['ports'] == ['80:80', '443:443', '443:443/udp']
    assert loaded['services']['grafana']['image'] == 'grafana/grafana:13.3.1'
    assert '3000:3000' not in compose_text(sample())
    assert '8428:8428' not in compose_text(sample())
    assert loaded['volumes']['grafana-data'] is None
    assert loaded['volumes']['vm-data'] is None


def test_ip_site_asks_letsencrypt_for_a_short_lived_certificate():
    spec = sample()
    text = caddy_text(spec)
    assert 'tls internal' not in text
    assert 'profile shortlived' in text
    assert 'default_sni 203.0.113.10' in text
    assert 'email admin@aegis-gate.ru' in text
    assert 'http://203.0.113.10' not in text
    assert 'Bearer ' + spec.write_token in text
    assert 'route {' in text
    assert 'respond "unauthorized" 401' in text
    assert text.count('reverse_proxy @writer victoriametrics:8428') == 1
    assert 'reverse_proxy grafana:3000' in text
    assert write_url(spec) == 'https://203.0.113.10/api/v1/write'


def test_domain_site_asks_for_a_public_certificate():
    text = caddy_text(sample(domain='metrics.example.com'))
    assert 'tls internal' not in text
    assert 'profile shortlived' not in text
    assert 'default_sni metrics.example.com' in text
    assert 'metrics.example.com' in text
    assert 'email admin@aegis-gate.ru' in text
    assert 'STRICT_TRANSPORT_SECURITY' in compose_text(sample(domain='metrics.example.com'))


def test_remote_script_installs_guard_and_keeps_volumes():
    spec = sample()
    script = remote_script(spec)
    assert 'GF_SECURITY_ADMIN_PASSWORD=' + spec.admin_password in script
    assert spec.write_token in script
    assert '[sshd]' in script
    assert '[recidive]' in script
    assert '198.51.100.10' in script
    assert 'rm -rf /data/caddy/certificates/local' in script
    assert 'Сертификат Let\'s Encrypt ещё не готов' in script
    assert 'docker compose restart caddy </dev/null' in script
    assert "curl -fsS" in script
    assert 'ufw --force enable' in script
    assert 'ufw limit' in script
    assert 'volume rm' not in script
    assert 'down -v' not in script
    assert '__' not in script
    assert 'GRAFANA_READY=1' in script
    assert "site=203.0.113.10" in script
    loaded = yaml.safe_load(datasource_text())
    assert loaded['datasources'][0]['url'] == 'http://victoriametrics:8428'
    assert loaded['datasources'][0]['isDefault'] is True


def test_generated_secrets_match_the_policy():
    for _ in range(20):
        remote_script(sample(admin_password=new_admin_password(), write_token=new_write_token()))


def test_rejects_a_weak_password_and_a_bad_address():
    try:
        remote_script(sample(admin_password='changeme'))
    except ValueError as exc:
        assert 'пароль' in str(exc)
    else:
        raise AssertionError('weak password was accepted')
    try:
        remote_script(sample(host='999.1.1.1'))
    except ValueError as exc:
        assert 'IPv4' in str(exc)
    else:
        raise AssertionError('bad address was accepted')


def test_env_update_keeps_unrelated_lines_and_redacts_secrets(tmp_path):
    path = tmp_path / 'grafana-env-test.env'
    path.write_text('# comment\nGRAFANA_SSH_PASSWORD=keep-me\nGRAFANA_ADMIN_PASSWORD=\n', encoding='utf-8')
    try:
        update_env_file(path, {'GRAFANA_ADMIN_PASSWORD': 'Aa1-bbbbbbbbbbbb'})
        text = path.read_text(encoding='utf-8')
    finally:
        path.unlink(missing_ok=True)
    assert '# comment' in text
    assert 'GRAFANA_SSH_PASSWORD=keep-me' in text
    assert 'GRAFANA_ADMIN_PASSWORD=Aa1-bbbbbbbbbbbb' in text
    assert redact('password Aa1-bbbbbbbbbbbb token', ['Aa1-bbbbbbbbbbbb']) == 'password *** token'
    assert parse_markers('шум\nGRAFANA_READY=1\nGRAFANA_URL=https://203.0.113.10\n')['GRAFANA_READY'] == '1'


def _memory() -> Session:
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def test_install_step_skips_the_password_and_the_token():
    from app.models import Node

    node = Node(
        name='Grafana',
        panel_url='',
        install_log='Ставлю Grafana\nЗахожу по SSH\nПароль: secret\nТокен записи: abc',
    )
    assert node.install_step() == 'Захожу по SSH'


def test_clean_vps_can_prepare_grafana_without_putting_it_in_the_pool(known_install_hosts):
    from app.routers.api import NodePatch, patch_node
    from app.xui_install import install_product, prepare_install

    assert install_product('grafana') == 'grafana'
    try:
        install_product('nginx')
    except ValueError as exc:
        assert 'Grafana' in str(exc)
    else:
        raise AssertionError('unknown product was accepted')
    with _memory() as session:
        node = prepare_install(
            session,
            flag='NL',
            name='Grafana',
            clash_name='',
            host='203.0.113.10',
            ssh_user='root',
            ssh_password='secret',
            ssh_port=22,
            kind='grafana',
        )
        assert node.install_kind == 'grafana'
        assert node.enabled is False
        assert 'Grafana' in node.install_log

        def runner(host, user, script, key, password, *, port=22):
            assert 'profile shortlived' in script
            assert host == '203.0.113.10'
            return 0, 'GRAFANA_URL=https://203.0.113.10\nGRAFANA_WRITE=https://203.0.113.10/api/v1/write\nGRAFANA_READY=1\n'

        apply_grafana_install(session, node.id, runner=runner)
        session.refresh(node)
        assert node.install_state == 'done'
        assert node.enabled is False
        assert node.panel_url == 'https://203.0.113.10'
        from app.routers.api import take_install_credentials
        handoff = json.loads(take_install_credentials(node.id, session).body)
        for field in ('password', 'write_token'):
            assert handoff[field] and handoff[field] not in node.install_log
        try:
            patch_node(node.id, NodePatch(enabled=True), session)
        except HTTPException as exc:
            assert exc.status_code == 400
        else:
            raise AssertionError('grafana was allowed into the subscription')
        session.refresh(node)
        assert node.enabled is False
