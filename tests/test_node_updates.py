from sqlmodel import Session, SQLModel, create_engine, select

from app import node_updates
from app.models import Node, UpdateNotification
from app.xui import XuiError

# Сценарий поведения фейковой панели по id ноды.
SCENARIOS: dict[int, dict] = {}
# Порядок вызова update_panel по именам — чтобы проверить очерёдность прогона.
CALLS: list[str] = []


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

    def server_status(self):
        self._guard()
        obj = {'cpu': '1.0'}
        state = self.s.get('xray_state', '')
        # Обновление ломает ядро: latest не поднят, прежняя версия — поднята.
        if self.s.get('xray_break_on_update'):
            installed = self.s.get('_installed', '')
            latest = (self.s.get('xray_versions') or [''])[0]
            state = 'running' if installed != latest else 'not running'
        if self.s.get('xray_always_broken'):
            state = 'not running'
        if state:
            obj['xray'] = {'state': state}
        return obj

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
        CALLS.append(self.node.name)
        return 'run-1'

    def get_update_status(self):
        self._guard()
        return {'state': self.s.get('update_status_state', 'success')}

    def install_xray(self, version):
        self._guard()
        if self.s.get('install_fail'):
            raise XuiError('install failed')
        self.s['_installed'] = version
        return {'success': True}


def _session():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def _node(session, id, name, *, enabled=True, rf_ok=False, xui='2.4.5', xray='25.9.8'):
    node = Node(
        id=id, name=name, panel_url=f'https://{name}', api_token='t',
        enabled=enabled, rf_ok=rf_ok, xui_version=xui, xray_version=xray,
    )
    session.add(node)
    session.commit()
    return node


def _reset(monkeypatch):
    SCENARIOS.clear()
    CALLS.clear()
    monkeypatch.setattr(node_updates, 'XuiClient', FakeXui)
    monkeypatch.setattr(node_updates.time, 'sleep', lambda _s: None)


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


def test_perform_update_skips_disabled_node(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', enabled=False)
        result = node_updates.perform_update(session, node)
        assert result.skipped is True
        assert result.ok is False


def test_perform_update_panel_only_when_xray_matches(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.11.1')
        SCENARIOS[1] = {'panel_current': '2.4.5', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        result = node_updates.perform_update(session, node)
        assert result.ok is True
        assert result.panel_updated is True
        assert result.xray_updated is False
        assert node.xui_version == '2.5.0'
        assert node.update_state == 'success'


def test_perform_update_updates_xray(monkeypatch):
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.5.0', xray='25.9.8')
        SCENARIOS[1] = {'panel_current': '2.5.0', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        result = node_updates.perform_update(session, node)
        assert result.ok is True
        assert result.xray_updated is True
        assert node.xray_version == '25.11.1'


def _notes(session) -> list[UpdateNotification]:
    return session.exec(select(UpdateNotification)).all()


def test_perform_update_notifies_on_disabled_skip(monkeypatch):
    """Выключенную ноду пропускаем и заводим уведомление — зона не пустая."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', enabled=False)
        result = node_updates.perform_update(session, node)
        assert result.skipped is True
        notes = _notes(session)
        assert len(notes) == 1
        assert notes[0].node_name == 'DE'
        assert 'выключена' in notes[0].message


def test_perform_update_no_notification_when_up_to_date(monkeypatch):
    """Версии совпадают — обновлять нечего, уведомлений не заводим."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.5.0', xray='25.11.1')
        SCENARIOS[1] = {'panel_current': '2.5.0', 'panel_latest': '2.5.0', 'xray_versions': ['25.11.1']}
        result = node_updates.perform_update(session, node)
        assert result.ok is True
        assert result.message == 'актуально'
        assert _notes(session) == []


def test_perform_update_rolls_back_xray_when_new_version_fails(monkeypatch):
    """Новое ядро не поднялось — откатываем на прежнюю версию, нода остаётся рабочей."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.5.0', xray='25.9.8')
        _node(session, 2, 'FI', rf_ok=True)
        _node(session, 3, 'NL', rf_ok=True)
        SCENARIOS[1] = {
            'panel_current': '2.5.0', 'panel_latest': '2.5.0',
            'xray_versions': ['25.11.1'], 'xray_break_on_update': True,
        }
        result = node_updates.perform_update(session, node)
        assert result.ok is False
        assert result.rolled_back is True
        assert result.xray_updated is False
        assert node.xray_version == '25.9.8'  # вернули прежнюю
        notes = _notes(session)
        assert any('откатили на 25.9.8' in n.message for n in notes)


def test_perform_update_reports_failed_rollback(monkeypatch):
    """Ни новая, ни прежняя версия не поднимаются — фиксируем провал отката."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.5.0', xray='25.9.8')
        _node(session, 2, 'FI', rf_ok=True)
        _node(session, 3, 'NL', rf_ok=True)
        SCENARIOS[1] = {
            'panel_current': '2.5.0', 'panel_latest': '2.5.0',
            'xray_versions': ['25.11.1'], 'xray_always_broken': True,
        }
        result = node_updates.perform_update(session, node)
        assert result.ok is False
        assert result.rolled_back is False
        assert node.xray_version == '25.9.8'
        notes = _notes(session)
        assert any('откат тоже не прошёл' in n.message for n in notes)


def test_check_updates_padded_versions_equal(monkeypatch):
    """'3.11.0' == '3.11' — панель не горит; отстающее ядро — горит (кейс #3)."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'NL', xui='3.11.0', xray='26.10.21')
        SCENARIOS[1] = {
            'panel_current': '3.11.0', 'panel_latest': '3.11',
            'xray_versions': ['26.10.23'],
        }
        info = node_updates.check_updates(node)
        assert info['panel_differs'] is False   # 3.11 == 3.11.0 — не обновляем
        assert info['xray_differs'] is True      # 26.10.23 > 26.10.21 — обновляем


def test_perform_update_panel_only_leaves_xray(monkeypatch):
    """kind='panel' трогает только панель, отстающее ядро остаётся как было."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.9.8')
        SCENARIOS[1] = {
            'panel_current': '2.4.5', 'panel_latest': '2.5.0',
            'xray_versions': ['25.11.1'],
        }
        result = node_updates.perform_update(session, node, kind='panel')
        assert result.ok is True
        assert result.panel_updated is True
        assert result.xray_updated is False
        assert node.xui_version == '2.5.0'
        assert node.xray_version == '25.9.8'   # ядро не тронуто


def test_perform_update_xray_only_leaves_panel(monkeypatch):
    """kind='xray' трогает только ядро, отстающая панель остаётся."""
    _reset(monkeypatch)
    with _session() as session:
        node = _node(session, 1, 'DE', xui='2.4.5', xray='25.9.8')
        _node(session, 2, 'FI', rf_ok=True)
        _node(session, 3, 'NL', rf_ok=True)
        SCENARIOS[1] = {
            'panel_current': '2.4.5', 'panel_latest': '2.5.0',
            'xray_versions': ['25.11.1'],
        }
        result = node_updates.perform_update(session, node, kind='xray')
        assert result.ok is True
        assert result.panel_updated is False
        assert result.xray_updated is True
        assert node.xui_version == '2.4.5'     # панель не тронута
        assert node.xray_version == '25.11.1'

