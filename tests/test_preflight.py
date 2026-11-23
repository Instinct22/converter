from sqlmodel import Session

from app import database, preflight, ssh_access
from app.models import AppSetting, Node
from app.xui_install import credential_key


def test_preflight_migrates_wal_snapshot_without_touching_live_data(tmp_path, monkeypatch):
    from sqlmodel import create_engine
    from sqlalchemy import event

    source = tmp_path / 'live.db'
    engine = create_engine(f'sqlite:///{source.as_posix()}')
    event.listen(engine, 'connect', database._sqlite_pragma)
    database.init_db(engine)
    with Session(engine) as db:
        n = Node(name='off', enabled=False, panel_url='', install_log='Логин: u\nПароль: old')
        db.add(n)
        db.commit()
        nid = n.id
        seen = []
        def verify_copy(session):
            assert session.get(AppSetting, credential_key(nid)) is not None
            assert 'old' not in session.get(Node, nid).install_log
            seen.append(nid)
            return []
        monkeypatch.setattr(preflight, 'check_nodes', verify_copy)
        assert preflight.check_database(source) == []
        assert seen == [nid]
        db.expire_all()
        assert 'old' in db.get(Node, nid).install_log
        assert db.get(AppSetting, credential_key(nid)) is None
    engine.dispose()


def test_first_install_check_does_not_create_a_live_db(tmp_path):
    path = tmp_path / 'master.db'
    assert preflight.check_database(path) == []
    assert not path.exists()


def test_preflight_reports_untrusted_nodes_without_logging_credentials(tmp_path, monkeypatch):
    from sqlmodel import create_engine
    engine = create_engine('sqlite://')
    database.init_db(engine)
    monkeypatch.setattr(ssh_access, 'KEY_DIR', tmp_path)
    with Session(engine) as session:
        session.add(Node(name='n', panel_url='http://untrusted.invalid/path-secret', api_token='test-token',
                         ssh_password='ssh-secret', ssh_auth='password', public_host='untrusted.invalid'))
        session.commit()
        messages = preflight.check_nodes(session)
        assert len(messages) == 2
        assert all(secret not in str(messages) for secret in ('path-secret', 'test-token', 'ssh-secret'))
    engine.dispose()
