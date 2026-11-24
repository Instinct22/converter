import json
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine, select

from app import bootstrap, database, main, mihomo, provision, ssh_access
from app.deps import credentials_ok
from app.models import (AppSetting, Client, ClientPingReport, ClientPlacement, ConfigDoc,
                        InboundTemplate, Node, NodeInbound, NodePingHour, NodeTemplateAssignment)
from app.routers import api
from app.settings import settings
from app.xui import XuiClient, XuiError, require_panel_transport
from app.xui_install import credential_key, migrate_install_logs


@pytest.fixture
def db(tmp_path):
    engine = create_engine(f'sqlite:///{(tmp_path / "test.db").as_posix()}')
    event.listen(engine, 'connect', database._sqlite_pragma)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    engine.dispose()


def node(name='first', enabled=True):
    return Node(name=name, panel_url='https://panel.example/test', api_token='test', enabled=enabled)


def client(name='anna'):
    return Client(name=name, slug=name, uuid=f'uuid-{name}', sub_token=f'token-{name}')


def panel(monkeypatch, responses):
    fake = object.__new__(XuiClient)
    fake.call = Mock(side_effect=responses)
    monkeypatch.setattr(provision, 'XuiClient', lambda *a, **kw: fake)
    monkeypatch.setattr(XuiClient, 'close', lambda self: None)
    return fake


def test_partial_revocation_survives_restart_and_retry(db, monkeypatch):
    good, offline, forgotten, user, other = node(), node('off', False), node('other'), client(), client('anna-long')
    db.add_all([good, offline, forgotten, user, other])
    db.commit()
    inbound = NodeInbound(node_id=offline.id, xui_inbound_id=8, port=443)
    db.add(inbound)
    db.commit()
    uid, nid, fid = user.id, offline.id, forgotten.id
    db.add(ClientPlacement(client_id=uid, inbound_id=inbound.id, node_id=nid, ok=True))
    db.add(ClientPingReport(client_id=uid))
    db.commit()
    unavailable = {nid, fid}
    deletions = []
    sightings = set()
    removed = set()

    class Panel:
        def __init__(self, target):
            self.nid = target.id

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def list_clients(self):
            sightings.add(self.nid)
            if self.nid in unavailable:
                raise XuiError('offline')
            rows = [{'client': {'email': 'anna-long', 'id': 'uuid-anna-long'}}]
            if self.nid not in removed:
                rows.append({'client': {'email': 'anna', 'id': 'uuid-anna'}, 'legacy_inbound_id': 8})
            return rows

        def del_client(self, inbound_id, uuid, email):
            removed.add(self.nid)
            deletions.append((self.nid, inbound_id, email))

    monkeypatch.setattr(provision, 'XuiClient', Panel)
    assert api.api_delete_client(uid, db)['ok'] is False
    assert db.get(Client, uid).enable is False
    assert json.loads(db.get(AppSetting, f'revoke_client/{uid}').value) == sorted([nid, fid])
    with pytest.raises(HTTPException) as err:
        api.patch_client(uid, api.ClientPatch(enable=True), db)
    assert err.value.status_code == 409
    assert db.exec(select(ClientPlacement)).one().node_id == nid
    forgotten.enabled = False
    db.commit()
    unavailable.clear()
    sightings.clear()
    with Session(db.get_bind()) as retry:
        assert api.api_delete_client(uid, retry)['ok'] is True
        assert retry.get(Client, uid) is None and retry.get(ClientPingReport, uid) is None
        assert retry.get(AppSetting, f'revoke_client/{uid}') is None
        assert retry.exec(select(Client)).one().slug == 'anna-long'
    assert {nid, fid} <= sightings
    assert all(entry[1:] == (8, 'anna') for entry in deletions)


def test_identity_conflict_never_selects_a_neighbour():
    a, b = client('a'), client('a-b')
    assert provision.match_master_client({'email': 'a-b-443-17'}, [a, b]) is b
    assert provision.match_master_client({'email': 'a-bc'}, [a, b]) is None
    with pytest.raises(XuiError):
        provision.match_master_client({'email': 'a', 'id': b.uuid}, [a, b])


@pytest.mark.parametrize('bad', [None, {}, [{'id': 1, 'port': 443}, {'id': 1, 'port': 443}],
                                 [{'id': 1, 'port': 443, 'settings': '{'}]])
def test_invalid_snapshot_preserves_local_inbound_and_settings(db, monkeypatch, bad):
    n = node()
    db.add(n)
    db.commit()
    db.add(NodeInbound(node_id=n.id, xui_inbound_id=17, port=443))
    db.commit()
    fake = panel(monkeypatch, [{'success': True, 'obj': bad}])
    with pytest.raises(XuiError):
        provision.sync_node(db, n)
    assert db.exec(select(NodeInbound)).one().xui_inbound_id == 17
    assert fake.call.call_count == 1


def test_legacy_client_sweep_preserves_each_inbound_id(monkeypatch):
    absent = {'success': False, 'raw': True, 'status': 404}
    rows = [{'id': i, 'port': 400+i, 'protocol': 'vless',
             'settings': json.dumps({'clients': [{'email': 'a', 'id': 'u'}]})} for i in [1, 2]]
    fake = panel(monkeypatch, [absent, {'success': True, 'obj': rows},
                               absent, {'success': True}, absent, {'success': True}])
    for row in fake.list_clients():
        fake.del_client(row['legacy_inbound_id'], row['client']['id'], 'a')
    assert [call.args[0] for call in fake.call.call_args_list if 'delClient' in call.args[0]] == [
        '/panel/api/inbounds/1/delClient/u', '/panel/api/inbounds/2/delClient/u']


@pytest.mark.parametrize('bad', [None, {}, [{}], [{'client': None}]])
def test_partial_client_list_is_not_evidence_of_absence(bad, monkeypatch):
    with pytest.raises(XuiError):
        panel(monkeypatch, [{'success': True, 'obj': bad}]).list_clients()


@pytest.mark.parametrize('fn', [provision.apply_node_templates, provision.reconcile_node_templates])
def test_invalid_template_selection_never_contacts_panel(db, monkeypatch, fn):
    n, keep, off = node(), InboundTemplate(name='keep', port=443), InboundTemplate(name='off', port=900, enabled=False)
    db.add_all([n, keep, off])
    db.commit()
    provision.set_node_template_ids(db, n.id, [keep.id])
    monkeypatch.setattr(provision, 'XuiClient', Mock(side_effect=AssertionError('remote operation')))
    for wrong in (off.id, 99999):
        assert not api._templates_ok(fn(db, n, [keep.id, wrong]))
        assert provision.node_template_ids(db, n.id) == [keep.id]


def test_reapplying_reality_preserves_published_identity_and_clients():
    tpl = InboundTemplate(name='t', port=443)
    old = provision.build_inbound_spec(tpl)
    old['id'] = 4
    old['settings'] = json.dumps({'clients': [{'email': 'existing'}]})
    def reality(spec):
        return json.loads(spec['streamSettings'])['realitySettings']
    new = provision._keep_remote_clients(old, provision.build_inbound_spec(tpl, existing=old))
    assert reality(new)['privateKey'] == reality(old)['privateKey']
    assert reality(new)['shortIds'] == reality(old)['shortIds']
    assert reality(new)['settings']['publicKey'] == reality(old)['settings']['publicKey']
    assert new['settings'] == old['settings']
    stream = json.loads(old['streamSettings'])
    del stream['realitySettings']['privateKey']
    with pytest.raises(XuiError):
        provision.build_inbound_spec(tpl, existing={**old, 'streamSettings': stream})


def test_custom_profile_and_explicit_empty_selection_survive_restarts(db):
    # Include a stock migration anchor as well as a locally maintained rule.
    raw = bootstrap.DEFAULT_YAML.read_text(encoding='utf-8').replace('type: fallback', 'type: fallback\n    interval: 30') + '# local\n'
    doc, n = ConfigDoc(yaml_text=raw), node()
    db.add_all([doc, n])
    db.commit()
    for _ in range(2):
        bootstrap.seed_if_empty(db)
        provision.ensure_default_node_templates(db)
        assert db.get(ConfigDoc, doc.id).yaml_text == raw
        assert provision.templates_for_node(db, n) == []


def test_assignment_migration_only_runs_for_database_without_assignment_table(db, monkeypatch):
    engine = db.get_bind()
    monkeypatch.setattr(database, 'engine', engine)
    n = node()
    db.add(n)
    db.commit()
    NodeTemplateAssignment.__table__.drop(engine)
    database.init_db()
    bootstrap.seed_if_empty(db)
    provision.ensure_default_node_templates(db)
    assert len(provision.templates_for_node(db, n)) == 2
    provision.set_node_template_ids(db, n.id, [])
    database.init_db()
    provision.ensure_default_node_templates(db)
    assert provision.templates_for_node(db, n) == []


def test_old_install_log_handoff_is_idempotent(db):
    n = node()
    n.install_log = 'Панель готова\nЛогин: old-user\nПароль: old-pass'
    db.add(n)
    db.commit()
    migrate_install_logs(db)
    assert 'old-pass' not in api.get_node(n.id, db)['install_log']
    assert json.loads(api.take_install_credentials(n.id, db).body)['username'] == 'old-user'
    migrate_install_logs(db)
    assert db.get(AppSetting, credential_key(n.id)) is None


def test_deleting_node_with_foreign_keys_preserves_unrelated_rows(db):
    n, keep, user, tpl = node(), node('keep'), client(), InboundTemplate(name='t', port=443)
    db.add_all([n, keep, user, tpl])
    db.commit()
    nid, keep_id = n.id, keep.id
    inbound = NodeInbound(node_id=nid, xui_inbound_id=4)
    db.add(inbound)
    db.commit()
    from app.models import utcnow
    db.add_all([NodeTemplateAssignment(node_id=nid, template_id=tpl.id), NodePingHour(node_id=nid, hour=utcnow()),
                ClientPlacement(node_id=nid, client_id=user.id, inbound_id=inbound.id),
                AppSetting(key=credential_key(nid), value='old')])
    db.commit()
    with pytest.raises(HTTPException) as err:
        api.delete_template(tpl.id, db)
    assert err.value.status_code == 409
    assert api.delete_node(nid, db)['ok']
    assert db.get(Node, keep_id) and db.get(Client, user.id)
    assert db.get(AppSetting, credential_key(nid)) is None
    assert api.delete_template(tpl.id, db)['ok']


def test_snapshot_query_count_is_independent_of_fleet_size(db):
    def count():
        statements = []
        def record(conn, cursor, statement, *args):
            statements.append(statement)
        engine = db.get_bind()
        event.listen(engine, 'before_cursor_execute', record)
        try:
            result = mihomo.subscription_inputs(db)
        finally:
            event.remove(engine, 'before_cursor_execute', record)
        return len(result[0]), len(statements)
    db.add(node())
    db.commit()
    assert count() == (1, 2)
    db.add_all([node(str(i)) for i in range(15)] + [node('disabled', False)])
    db.commit()
    assert count() == (16, 2)


def test_tls_redirect_guard_and_loopback_compatibility():
    for url in ('http://localhost/panel', 'http://[::1]:8080/panel', 'https://node.example/panel'):
        require_panel_transport(url)
    with pytest.raises(XuiError):
        require_panel_transport('http://node.example/')
    with XuiClient(node()) as xui:
        xui._check_destination(httpx.Request('GET', xui.base + '/other'))
        with pytest.raises(XuiError):
            xui._check_destination(httpx.Request('GET', 'http://panel.example/other'))


def test_host_identity_failure_does_not_downgrade_ssh_or_try_password(monkeypatch):
    n = node()
    n.ssh_auth, n.ssh_password = 'both', 'test'
    monkeypatch.setattr(ssh_access, 'ensure_fleet_key', lambda: None)
    monkeypatch.setattr(ssh_access, 'public_key_line', lambda: 'test')
    call = Mock(side_effect=ssh_access.HostIdentityError('unknown host key'))
    assert ssh_access.adopt_node(n, runner=call).ok is False
    assert call.call_count == 1 and call.call_args.args[0] == 'key'
    assert n.ssh_auth == 'both' and n.ssh_password == 'test'


@pytest.mark.parametrize('password', ['', 'changeme'])
def test_unsafe_admin_settings_refuse_startup_and_login(monkeypatch, password):
    monkeypatch.setattr(settings, 'admin_password', password)
    with pytest.raises(ValueError):
        settings.validate_admin_password()
    assert not credentials_ok(settings.admin_username, password)


def test_signing_key_is_published_atomically(tmp_path, monkeypatch):
    from app import settings as config
    monkeypatch.setattr(config, 'DATA_DIR', tmp_path)
    monkeypatch.setattr(settings, 'session_secret', '')
    with ThreadPoolExecutor(max_workers=8) as workers:
        values = list(workers.map(lambda _: config.session_signing_key(), range(24)))
    assert set(values) == {(tmp_path / 'session_secret').read_text()}
    assert len(values[0]) >= 32


def test_http_reports_reject_oversize_and_invalid_payloads():
    http = TestClient(main.app)
    assert http.post('/sub/example/report', content=b' ' * (256 * 1024 + 1)).status_code == 413
    assert http.post('/sub/example/report', content='[]').status_code == 400


def test_partial_template_creation_keeps_working_port_and_firewall(db, monkeypatch):
    n, old, new = node(), InboundTemplate(name='old', port=443), InboundTemplate(name='new', port=8443)
    db.add_all([n, old, new])
    db.commit()
    provision.set_node_template_ids(db, n.id, [old.id])
    fake = panel(monkeypatch, [{'success': True, 'obj': [{'id': 5, 'port': 443}]},
                               {'success': False, 'msg': 'refused'}])
    firewall = Mock()
    monkeypatch.setattr(provision, 'sync_node_firewall', firewall)
    assert not api._templates_ok(provision.reconcile_node_templates(db, n, [new.id]))
    assert provision.node_template_ids(db, n.id) == [old.id]
    assert [call.args[0] for call in fake.call.call_args_list] == [
        '/panel/api/inbounds/list', '/panel/api/inbounds/add']
    firewall.assert_not_called()


def test_sni_retry_only_publishes_after_panel_acknowledges(db, monkeypatch):
    n = node()
    tpl = InboundTemplate(name='t', port=443, server_names='main.example', extra_snis='alt.example')
    db.add(n)
    db.commit()
    row = NodeInbound(node_id=n.id, xui_inbound_id=2, port=443, remark='t', server_names='old.example')
    db.add(row)
    db.commit()
    push = Mock(side_effect=[XuiError('offline'), True])
    monkeypatch.setattr(provision, 'push_server_names', push)
    assert not api._templates_ok(provision.sync_template_fields(db, n, [tpl]))
    assert row.server_names == 'old.example'
    provision.sync_template_fields(db, n, [tpl])
    assert row.server_names == 'main.example'
    assert push.call_args.args[-1] == ['main.example', 'alt.example']


def test_overlapping_reports_increment_same_hour(db, monkeypatch):
    from app.client_pings import _recent
    from datetime import datetime, timezone
    from app.database import get_session
    _recent.clear()
    db.add_all([node('first'), client('one'), client('two')])
    db.commit()
    engine = db.get_bind()
    def sessions():
        with Session(engine) as current:
            yield current
    monkeypatch.setitem(main.app.dependency_overrides, get_session, sessions)
    data = {'servers': [{'server': 'first', 'median_ms': 120, 'ok': 2, 'failed': 0,
                         'at': datetime.now(timezone.utc).isoformat()}]}
    def send(name):
        http = TestClient(main.app)
        try:
            return http.post('/sub/token-' + name + '/report', json=data).status_code
        finally:
            http.close()
    with ThreadPoolExecutor(max_workers=2) as workers:
        assert list(workers.map(send, ['one', 'two'])) == [204, 204]
    assert db.exec(select(NodePingHour)).one().reports == 2


def test_protection_page_with_a_node_has_a_ban_cell(db, monkeypatch):
    from app.database import get_session
    db.add(node())
    db.commit()
    engine = db.get_bind()
    def session_override():
        with Session(engine) as current:
            yield current
    monkeypatch.setitem(main.app.dependency_overrides, get_session, session_override)
    http = TestClient(main.app)
    assert http.post('/login', data={'username': settings.admin_username, 'password': settings.admin_password},
                     follow_redirects=False).status_code == 302
    result = http.get('/protection')
    assert result.status_code == 200 and '>Вход<' in result.text and '<td data-guard="banned">0</td>' in result.text


def test_ipv6_and_ipv4_rules_in_modern_and_legacy_yaml(db):
    from app.firewall import wanted_ports
    bootstrap.seed_if_empty(db)
    n = node()
    n.public_host = '2001:db8::21'
    both = node('v4')
    both.public_host = '192.0.2.22'
    db.add_all([n, both])
    db.commit()
    assert 443 in wanted_ports(n, set())
    doc = db.exec(select(ConfigDoc)).one()
    for profile in (doc.yaml_text, doc.yaml_text.replace('XUI_PROVIDERS_', 'XUI_PROXIES_')):
        doc.yaml_text = profile
        db.commit()
        body = mihomo.render_profile(db, client())
        assert 'IP-CIDR6,2001:db8::21/128,DIRECT' in body
        assert 'IP-CIDR,192.0.2.22/32,DIRECT' in body


def test_yaml_omits_online_probe_and_keeps_traffic(db, monkeypatch):
    from app.routers import sub
    from app import overview
    n, person = node(), client()
    db.add_all([n, person])
    db.commit()
    bootstrap.seed_if_empty(db)
    fake = panel(monkeypatch, [])
    monkeypatch.setattr(overview, 'XuiClient', lambda *a, **kw: fake)
    fake.inbounds = Mock(return_value=[{'settings': {'clients': [{'id': person.uuid, 'email': person.slug}]},
                                       'clientStats': [{'email': person.slug, 'up': 10, 'down': 20}]}])
    fake.onlines = Mock(return_value=[person.slug])
    result = sub.serve_yaml(person.sub_token, db)
    assert 'upload=10; download=20;' in result.headers['subscription-userinfo']
    fake.onlines.assert_not_called()


@pytest.mark.parametrize('enabled', [True, False])
def test_browser_subscription_only_offers_the_canonical_link(db, monkeypatch, enabled):
    from app.database import get_session
    from app.routers import sub
    from app.sub_link import client_sub_url

    person = client()
    person.name = 'Private subscriber name'
    person.enable = enabled
    db.add(person)
    db.commit()
    monkeypatch.setitem(main.app.dependency_overrides, get_session, lambda: db)
    probe = Mock(side_effect=AssertionError('The browser page should not query nodes'))
    monkeypatch.setattr(sub, 'probe_nodes_presence', probe)
    web = TestClient(main.app)
    response = web.get(f'/clash/{person.sub_token}?html=1', headers={'Accept': 'text/html'})
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    assert 'subscription-userinfo' not in response.headers
    assert 'Скопировать ссылку' in response.text
    assert f'data-url="{client_sub_url(person)}"' in response.text
    for private in (person.name, person.uuid, '/mihomo/', 'yaml=', '3x-ui', 'Mihomo'):
        assert private not in response.text
    assert web.get('/sub/unknown', headers={'Accept': 'text/html'}).status_code == 404
    probe.assert_not_called()


def test_failed_remote_probe_and_partial_fleet_are_visible(db, monkeypatch):
    n = node()
    db.add(n)
    db.commit()
    fake = panel(monkeypatch, [])
    monkeypatch.setattr(api, 'XuiClient', lambda *a, **kw: fake)
    fake.server_status = Mock(side_effect=XuiError('offline'))
    fake.panel_settings = Mock(side_effect=XuiError('offline'))
    assert api.test_node(n.id, db)['ok'] is False
    partial = api._fleet_result([1, 2], [(['first ok'], {'id': 1, 'ok': True}), ValueError()])
    assert not partial['ok'] and partial['nodes'] == [{'id': 1, 'ok': True}]
    assert '2' in partial['logs'][-1]


def test_delete_requires_panel_to_confirm_absence(db, monkeypatch):
    n, user = node(), client()
    db.add_all([n, user])
    db.commit()
    still_present = {'success': True, 'obj': [{'email': user.slug, 'id': user.uuid}]}
    panel(monkeypatch, [still_present, {'success': True}, still_present])
    assert api.api_delete_client(user.id, db)['ok'] is False
    assert not db.get(Client, user.id).enable


def test_empty_template_body_cannot_clear_assignments(db):
    n = node()
    db.add(n)
    db.commit()
    for handler in (api.api_apply_node_templates, api.api_refresh_node_templates):
        with pytest.raises(HTTPException) as exc:
            handler(n.id, api.ProvisionIn(), db)
        assert exc.value.status_code == 422


def test_update_settings_sends_full_payload_and_requires_ack(monkeypatch):
    fake = panel(monkeypatch, [{'success': True}, {'success': False}])
    settings_payload = {'subEnable': False, 'other': 'keep'}
    fake.update_settings(settings_payload)
    fake.call.assert_called_once_with('/panel/api/setting/update', settings_payload)
    with pytest.raises(XuiError):
        fake.update_settings(settings_payload)


def test_grant_in_progress_finishes_before_revoke_and_cannot_restore_deleted_user(db, monkeypatch):
    from threading import Event
    person, n = client(), node()
    db.add_all([person, n])
    db.commit()
    uid, engine = person.id, db.get_bind()
    granting, deleting, release = Event(), Event(), Event()
    state = []
    def grant(*args):
        granting.set()
        assert release.wait(5)
        state.append('granted')
        return []
    def delete_lock(cid):
        deleting.set()
        return provision.client_access_lock(cid)
    def run_grant():
        with Session(engine) as session:
            return provision.provision_client(session, session.get(Client, uid))
    def run_delete():
        with Session(engine) as session:
            return api.api_delete_client(uid, session)
    monkeypatch.setattr(provision, '_provision_client_node', grant)
    monkeypatch.setattr(api, 'client_access_lock', delete_lock)
    fake = panel(monkeypatch, [])
    def list_clients():
        return [{'email': 'anna', 'id': 'uuid-anna'}] if state == ['granted'] else []
    fake.list_clients = list_clients
    fake.del_client = lambda *a, **kw: state.append('revoked')
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(run_grant)
        assert granting.wait(5)
        second = workers.submit(run_delete)
        try:
            assert deleting.wait(5)
            assert state == []
        finally:
            release.set()
        first.result(timeout=10)
        assert second.result(timeout=10)['ok']
    assert state == ['granted', 'revoked']
    assert provision.provision_client(db, person) == ['Клиент уже удалён']


def test_http_install_preserves_handoff_and_leaves_node_disabled(db):
    from app.xui_install import apply_install_result
    n = node()
    n.install_state = 'installing'
    n.public_host = '192.0.2.2'
    db.add(n)
    db.commit()
    result = 'MASTER_URL=http://192.0.2.2/panel\nMASTER_USER=test\nMASTER_PASS=pw\nMASTER_TOKEN=t'
    apply_install_result(db, n.id, runner=lambda *a, **kw: (0, result))
    db.refresh(n)
    assert not n.enabled and 'HTTPS' in n.last_error
    assert json.loads(api.take_install_credentials(n.id, db).body)['password'] == 'pw'


def test_admin_cookie_and_request_log_configuration(monkeypatch):
    import os
    import subprocess
    import sys
    import uvicorn
    captured = Mock()
    monkeypatch.setattr(uvicorn, 'run', captured)
    main.run()
    assert captured.call_args.kwargs['access_log'] is False
    check = ("from fastapi.testclient import TestClient; from app.main import app; "
             "from app.settings import settings; "
             "r=TestClient(app,base_url='https://example.test').post('/login', "
             "data={'username':settings.admin_username,'password':settings.admin_password},follow_redirects=False); "
             "assert r.status_code==302 and 'secure' in r.headers['set-cookie'].lower()")
    subprocess.run([sys.executable, '-c', check], check=True,
                   env={**os.environ, 'PUBLIC_BASE_URL': 'https://example.test'})


def test_long_provider_names_remain_distinct_and_hidden_inbound_stays_hidden():
    n = node('longname' * 12)
    n.id, n.public_host = 1, '192.0.2.1'
    first = 'a' * 50
    names = ['main.example', first + '1.example', first + '2.example']
    inbound = NodeInbound(node_id=1, xui_inbound_id=1, public_key='key', port=443,
                          snis_locked=True, server_names=','.join(names))
    hidden = NodeInbound(node_id=1, xui_inbound_id=2, public_key='key', port=8443,
                         server_names='hidden.test', use_in_sub=False)
    inbounds = {1: [inbound, hidden]}
    keys = [key for key, _ in mihomo.published_proxies([n], client(), inbounds)]
    assert len(set(keys)) == 3 and max(map(len, keys)) == 64
    proxies, _ = mihomo.collect_proxies([n], inbounds, client())
    assert {proxy['servername'] for proxy in proxies} == set(names)


def test_update_inbound_keeps_existing_request_contract(monkeypatch):
    xui = panel(monkeypatch, [{'success': True}])
    spec = {'id': 7, 'streamSettings': '{"network":"grpc"}'}
    original = dict(spec)
    xui.update_inbound(7, spec)
    xui.call.assert_called_once_with('/panel/api/inbounds/update/7', original)
    assert spec == original


def test_node_card_fetches_panel_token_only_on_explicit_admin_request(db, monkeypatch):
    from app.database import get_session
    n = node()
    n.api_token = 'example-panel-token'
    n.install_log = 'done'
    db.add(n)
    db.commit()
    engine = db.get_bind()
    def sessions():
        with Session(engine) as current:
            yield current
    monkeypatch.setitem(main.app.dependency_overrides, get_session, sessions)
    http = TestClient(main.app)
    endpoint = f'/api/nodes/{n.id}/panel-token'
    assert http.post(endpoint).status_code == 401
    assert http.post('/login', data={'username': settings.admin_username, 'password': settings.admin_password},
                     follow_redirects=False).status_code == 302
    card = http.get(f'/nodes/{n.id}')
    assert card.status_code == 200 and 'show-saved-token' in card.text
    assert n.api_token not in card.text and n.api_token not in http.get(f'/api/nodes/{n.id}').text
    response = http.post(endpoint)
    assert response.json() == {'token': n.api_token}
    assert response.headers['cache-control'] == 'no-store'
