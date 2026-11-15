from sqlmodel import Session, SQLModel, create_engine

from app import node_updates
from app.models import Node
from app.xui import XuiError

# Сценарий поведения фейковой панели по id ноды.
SCENARIOS: dict[int, dict] = {}


class FakeXui:
    def __init__(self, node, timeout=12.0):
        self.node = node
        self.s = SCENARIOS.get(node.id or 0, {})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def _guard(self):
        if self.s.get('offline'):
            raise XuiError('нет связи с панелью')

    def get_panel_update_info(self):
        self._guard()
        return {
            'currentVersion': self.s.get('panel_current', ''),
            'latestVersion': self.s.get('panel_latest', ''),
        }

    def get_xray_versions(self):
        self._guard()
        return list(self.s.get('xray_versions', []))

    def update_panel(self):
        self._guard()
        self.s['_panel_updated'] = True
        return 'run-1'

    def install_xray(self, version):
        self._guard()
        if self.s.get('install_fail'):
            raise XuiError('install failed')
        self.s['_installed'] = version
        return {'success': True}


class _NoThread:
    """Заглука threading.Thread: .start() ничего не делает (фон не трогаем в тесте)."""

    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        return None


def _session():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def _node(session, id, name, *, enabled=True, xui='2.4.5', xray='25.9.8'):
    node = Node(
        id=id, name=name, panel_url=f'https://{name}', api_token='t',
        enabled=enabled, xui_version=xui, xray_version=xray,
    )
    session.add(node)
    session.commit()
    return node


def _reset(monkeypatch):
    SCENARIOS.clear()
    monkeypatch.setattr(node_updates, 'XuiClient', FakeXui)
    monkeypatch.setattr(node_updates.threading, 'Thread', _NoThread)


def test_check_updates_detects_diffs(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.9.8')
        SCENARIOS[1] = {'panel_current': '2.4.5', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        info = node_updates.check_updates(node)
        assert info['panel_differs'] is True
        assert info['xray_differs'] is True
        assert node.panel_latest_version == '2.5.0'
        assert node.xray_latest_version == '25.11.1'


def test_check_updates_no_diff_when_versions_match(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.5.0', xray='25.11.1')
        SCENARIOS[1] = {'panel_current': '2.5.0', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        info = node_updates.check_updates(node)
        assert info['panel_differs'] is False
        assert info['xray_differs'] is False


def test_check_updates_padded_versions_equal(monkeypatch):
    """'3.11' == '3.11.0' — панель не горит; отстающее ядро — горит."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'NL', xui='3.11.0', xray='26.10.21')
        SCENARIOS[1] = {'panel_current': '3.11.0', 'panel_latest': '3.11', 'xray_versions': ['26.10.23']}
        info = node_updates.check_updates(node)
        assert info['panel_differs'] is False


def test_start_update_panel_sets_running(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.9.8')
        SCENARIOS[1] = {'panel_current': '2.4.5', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        res = node_updates.start_update(session, node, 'panel')
        assert res['ok'] is True
        assert res['state'] == 'running'
        assert res['from'] == '2.4.5'
        assert res['to'] == '2.5.0'
        assert SCENARIOS[1].get('_panel_updated') is True
        session.refresh(node)
        assert node.update_state == 'running'
        assert node.update_kind == 'panel'
        assert node.update_prev_version == '2.4.5'
        assert node.update_target_version == '2.5.0'


def test_start_update_xray_sets_running(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.9.8')
        SCENARIOS[1] = {'panel_current': '2.4.5', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        res = node_updates.start_update(session, node, 'xray')
        assert res['ok'] is True
        assert res['to'] == '25.11.1'
        assert SCENARIOS[1].get('_installed') == '25.11.1'


def test_start_update_rejects_when_already_current(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.5.0', xray='25.9.8')
        SCENARIOS[1] = {'panel_current': '2.5.0', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        res = node_updates.start_update(session, node, 'panel')
        assert res['ok'] is False
        assert 'актуальн' in res['message']


def test_start_update_rejects_disabled_node(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', enabled=False, xui='2.4.5', xray='25.9.8')
        SCENARIOS[1] = {'panel_current': '2.4.5', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        res = node_updates.start_update(session, node, 'panel')
        assert res['ok'] is False


def test_start_update_rejects_when_running(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.9.8')
        node.update_state = 'running'
        session.add(node)
        session.commit()
        SCENARIOS[1] = {'panel_current': '2.4.5', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        res = node_updates.start_update(session, node, 'panel')
        assert res['ok'] is False


def test_start_rollback_xray_installs_prev(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.5.0', xray='25.9.8')
        node.update_state = 'failed'
        node.update_kind = 'xray'
        node.update_prev_version = '25.9.8'
        session.add(node)
        session.commit()
        SCENARIOS[1] = {}
        res = node_updates.start_rollback(session, node)
        assert res['ok'] is True
        assert res['to'] == '25.9.8'
        assert SCENARIOS[1].get('_installed') == '25.9.8'
        session.refresh(node)
        assert node.update_state == 'running'


def test_start_rollback_panel_unavailable(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.9.8')
        node.update_state = 'failed'
        node.update_kind = 'panel'
        node.update_prev_version = '2.4.5'
        session.add(node)
        session.commit()
        res = node_updates.start_rollback(session, node)
        assert res['ok'] is False
        assert 'панели' in res['message']

