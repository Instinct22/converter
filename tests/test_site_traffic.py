import json
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, select

from app.database import get_session
from app.main import app
from app.models import SiteFirst, SiteMinute, SiteSeen
from app.settings import settings
from app.site_traffic import ingest_access_log, is_bot, site_series


CHROME = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
)
YANDEX = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/120.0.0.0 YaBrowser/24.1.0.0 Safari/537.36'
)
GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'


def _memory():
    engine = create_engine(
        'sqlite://',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


def _line(ts: int, agent: str, uri: str, ip: str) -> str:
    return json.dumps({
        'ts': ts,
        'request': {
            'remote_ip': ip,
            'host': 'aegis-gate.ru',
            'uri': uri,
            'headers': {'User-Agent': [agent]},
        },
    })


def test_browser_is_human_and_known_robots_are_not():
    assert is_bot(CHROME) is False
    assert is_bot(YANDEX) is False
    assert is_bot(GOOGLEBOT) is True
    assert is_bot('curl/8.4.0') is True
    assert is_bot('') is True
    assert is_bot('python-requests/2.32') is True


def test_ingest_counts_live_people_once_and_keeps_bots_in_rps(monkeypatch, tmp_path):
    monkeypatch.setattr('app.site_traffic._salt', lambda: b'salt')
    now = 1_763_000_000
    now -= now % 60
    now += 120
    stamp = now - 90
    lines = [_line(stamp, CHROME, '/', '203.0.113.8') for _ in range(60)]
    lines.append(_line(stamp, GOOGLEBOT, '/', '198.51.100.9'))
    lines.append(_line(stamp, CHROME, '/assets/icon.png', '203.0.113.8'))
    lines.append(_line(stamp, CHROME, '/connect', '203.0.113.9'))
    (tmp_path / 'aegis.log').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    engine = _memory()
    with Session(engine) as session:
        assert ingest_access_log(session, tmp_path, now) > 0
        assert ingest_access_log(session, tmp_path, now) == 0
        minute = session.exec(select(SiteMinute)).one()
        assert minute.requests == 63
        assert minute.human_requests == 62
        assert len(session.exec(select(SiteSeen)).all()) == 2
        assert len(session.exec(select(SiteFirst)).all()) == 2
        series = site_series(session, '1h', datetime.fromtimestamp(now, timezone.utc))
    bucket = stamp - stamp % 60
    point = next(item for item in series['rps']['points'] if item['t'] == bucket)
    assert point['all'] == 63 / 60
    assert point['human'] == 62 / 60
    people = next(item for item in series['people']['points'] if item['t'] == bucket)
    assert people['active'] == 2
    assert people['new'] == 2
    assert series['people']['unique'] == 2
    assert series['people']['new'] == 2
    assert series['samples'] == 63


def test_site_page_and_api_require_login_and_name_the_graphs(monkeypatch, tmp_path):
    monkeypatch.setattr('app.site_traffic.LOG_DIR', tmp_path)
    engine = _memory()

    def _session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session
    try:
        http = TestClient(app)
        denied = http.get('/api/site')
        assert denied.status_code == 401
        redirected = http.get('/users', follow_redirects=False)
        assert redirected.status_code == 302
        assert redirected.headers['location'] == '/site'
        locked = http.get('/site', follow_redirects=False)
        assert locked.status_code == 302
        http.post('/login', data={'username': settings.admin_username, 'password': settings.admin_password})
        page = http.get('/site')
        assert page.status_code == 200
        assert 'Запросы в секунду' in page.text
        assert 'Приток живых' in page.text
        assert 'Журнал Caddy ещё пуст' in page.text
        assert 'href="/site" title="Сайт" class="active"' in page.text
        body = http.get('/api/site?span=6h')
        assert body.status_code == 200
        assert body.json()['span'] == '6h'
        assert body.json()['samples'] == 0
    finally:
        app.dependency_overrides.pop(get_session, None)
