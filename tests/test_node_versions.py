from app.models import Node
from app.overview import _status_bits, store_versions
from app.xui import clean_version, versions_from_status


def test_versions_from_fresh_panel_status():
    """Свежие 3x-ui: версия панели в panelVersion, ядро — в xray.version."""
    obj = {
        'panelVersion': '2.6.2',
        'xray': {'version': '25.9.8', 'running': True, 'state': 'running'},
    }
    assert versions_from_status(obj) == ('2.6.2', '25.9.8')


def test_versions_from_old_panel_status():
    """3x-ui 2.5.x: версии панели в ответе нет вовсе, ядро — в плоском xrayVersion."""
    obj = {'xrayVersion': '1.8.7', 'xray': {'running': True, 'state': 'running'}}
    assert versions_from_status(obj) == ('', '1.8.7')


def test_versions_when_panel_reports_nothing():
    assert versions_from_status({'cpu': '3.0', 'xray': {}}) == ('', '')
    assert versions_from_status(None) == ('', '')
    assert versions_from_status({'panelVersion': 'N/A', 'xray': {'version': ''}}) == ('', '')


def test_clean_version_drops_placeholder_noise():
    for junk in ('', None, '   ', 'N/A', 'n/a', 'unknown', 'None', 'null', 'неизвестно'):
        assert clean_version(junk) == ''
    assert clean_version('2.6.2') == '2.6.2'
    assert clean_version(' 25.9.8 ') == '25.9.8'


def test_status_bits_carry_versions_from_the_same_status_call():
    bits = _status_bits({
        'cpu': '12.0',
        'panelVersion': '2.6.2',
        'xray': {'version': '25.9.8', 'state': 'running'},
        'tcpCount': 3,
    })
    assert bits['panel_version'] == '2.6.2'
    assert bits['xray_version'] == '25.9.8'
    assert bits['xray'] == 'running'
    assert bits['tcp'] == 3


def test_store_versions_saves_both_and_stamps_time():
    node = Node(name='DE', panel_url='https://de', api_token='a')
    assert store_versions(node, {'panel_version': '2.6.2', 'xray_version': '25.9.8'}) is True
    assert (node.xui_version, node.xray_version) == ('2.6.2', '25.9.8')
    assert node.version_checked_at is not None


def test_store_versions_does_not_blank_out_known_values():
    """Старая панель не отдаёт версию панели — находку нельзя затирать пустым."""
    node = Node(name='DE', panel_url='https://de', api_token='a')
    store_versions(node, {'panel_version': '2.6.2', 'xray_version': '25.9.8'})
    checked_at = node.version_checked_at

    assert store_versions(node, {'panel_version': '', 'xray_version': '25.11.1'}) is True
    assert (node.xui_version, node.xray_version) == ('2.6.2', '25.11.1')

    # версий нет вообще — ничего не пишем и время проверки не двигаем
    assert store_versions(node, {}) is False
    assert node.version_checked_at == checked_at
