from fastapi.testclient import TestClient

from app.fail2ban import (
    _status_python,
    guard_totals,
    jail_config,
    parse_ban_lines,
    parse_guard_output,
    until_label,
    valid_ban_ip,
)
from app.main import app
from app.settings import settings


def test_jail_watches_ssh_and_repeat_bans_only():
    text = jail_config(22, '127.0.0.1/8 ::1 5.180.174.204')
    assert 'port = 22' in text
    assert 'maxretry = 4' in text
    assert 'findtime = 10m' in text
    assert 'bantime = 1h' in text
    assert '[recidive]' in text
    assert 'bantime = 1w' in text
    assert 'maxretry = 3' in text
    assert '5.180.174.204' in text
    assert '443' not in text


def test_parse_guard_status():
    view = parse_guard_output(
        '! installed\nSTATE protecting\nBANNED 2\nDAY 5\nNOTE ok\nBAN\t1.2.3.4\tsshd\t3\t2400\t8\n'
    )
    assert view.state == 'protecting'
    assert view.banned == 2
    assert view.day == 5
    assert view.installed is True
    bans = parse_ban_lines('BAN\t1.2.3.4\tsshd\t3\t2400\t8\nBAN\tnot-an-ip\tsshd\t1\t10\t1\n')
    assert len(bans) == 1
    assert bans[0].ip == '1.2.3.4'
    assert bans[0].reason == 'подбор SSH'
    assert bans[0].times == 3
    assert bans[0].failures == 8
    assert bans[0].until == until_label(2400)


def test_remote_status_script_compiles():
    src = _status_python()
    code = src.split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    compile(code, '<fail2ban-status>', 'exec')


def test_protection_page_renders():
    from app.database import init_db

    init_db()
    client = TestClient(app)
    login = client.post(
        '/login',
        data={'username': settings.admin_username, 'password': settings.admin_password},
        follow_redirects=False,
    )
    assert login.status_code == 302
    page = client.get('/protection')
    assert page.status_code == 200
    assert 'Поставить защиту' in page.text
    assert 'Клиентские порты не баним' in page.text
    assert "loadGuard(null, '/api/protection/refresh')" in page.text
    assert 'Перевести на ключ' in page.text
    assert 'Сверить порты' in page.text
    assert '/api/protection/ports' in page.text
    assert '>Вход<' in page.text
    assert 'data-guard="banned"' in page.text or 'Серверов нет' in page.text


def test_guard_totals_include_banned_with_the_rest_of_the_snapshot():
    totals = guard_totals([
        {'id': 1, 'state': 'protecting', 'banned': 2, 'day': 5, 'note': 'ok'},
        {'id': 2, 'state': 'missing', 'banned': 0, 'day': 1, 'note': ''},
    ])
    assert totals['banned_now'] == 2
    assert totals['banned_day'] == 6
    assert totals['protecting'] == 1
    assert totals['total'] == 2
    assert [row['banned'] for row in totals['nodes']] == [2, 0]


def test_ban_ip_must_look_like_address():
    assert valid_ban_ip('91.240.44.18')
    assert valid_ban_ip('2001:db8::1')
    assert not valid_ban_ip('91.240.44.18; id')
    assert not valid_ban_ip('')
