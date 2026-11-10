from app.reality_scan import scan_view, sort_scans


def test_scan_view_marks_feasible_target():
    row = scan_view('Estonia-01', 5, {
        'latencyMs': 42,
        'feasible': True,
        'tls13': True,
        'h2': True,
        'x25519': True,
        'certValid': True,
    })
    assert row['ok'] is True
    assert row['latency_ms'] == 42
    assert row['feasible'] is True
    assert row['note'] == ''


def test_scan_view_explains_unsuitable_target():
    row = scan_view('Finland-01', 1, {
        'latencyMs': 80,
        'feasible': False,
        'tls13': True,
        'h2': False,
        'x25519': True,
        'certValid': False,
        'reason': '',
    })
    assert row['feasible'] is False
    assert 'нет HTTP/2' in row['note']
    assert 'сертификат не подошёл' in row['note']


def test_panel_network_error_stays_on_that_server(monkeypatch):
    from app.models import Node
    from app.reality_scan import scan_target_on_node

    class Boom:
        def __enter__(self):
            raise OSError('timed out')

        def __exit__(self, *args):
            return None

    monkeypatch.setattr('app.reality_scan.XuiClient', lambda *args, **kwargs: Boom())
    row = scan_target_on_node(Node(name='Italy-01', panel_url='https://panel.example'), 'site.example:443', '')
    assert row['ok'] is False
    assert row['name'] == 'Italy-01'
    assert row['error'] == 'нет связи с панелью'


def test_sort_scans_puts_fastest_first():
    rows = sort_scans([
        {'ok': False, 'latency_ms': 0, 'name': 'Italy-01'},
        {'ok': True, 'latency_ms': 90, 'name': 'Germany-01'},
        {'ok': True, 'latency_ms': 30, 'name': 'Estonia-01'},
    ])
    assert [row['name'] for row in rows] == ['Estonia-01', 'Germany-01', 'Italy-01']
