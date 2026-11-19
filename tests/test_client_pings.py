import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, select

from app.client_pings import (
    _recent,
    as_moscow,
    availability_counts,
    client_server_chart,
    ingest_report,
    node_reporters,
    normalize_server,
    percentile,
    purge_old_ping_hours,
    recent_nodes,
    reporter_buckets,
    server_faces,
)
from app.settings import settings
from app.database import get_session
from app.main import app
from app.models import Client, ClientPingReport, Node, NodePingHour


def _memory():
    engine = create_engine(
        'sqlite://',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


def _seed(session: Session) -> tuple[Client, Node]:
    client = Client(name='Офис', slug='office', uuid='u-1', sub_token='tok', enable=True)
    node = Node(
        name='Sweden-01',
        clash_name='Sweden-01',
        panel_url='https://203.0.113.10:2053/x',
        public_host='203.0.113.10',
        flag='se',
        enabled=True,
    )
    session.add(client)
    session.add(node)
    session.commit()
    session.refresh(client)
    session.refresh(node)
    return client, node


def test_normalize_drops_the_flag():
    assert normalize_server('🇸🇪 Sweden-01') == 'sweden-01'
    assert normalize_server('Sweden-01') == 'sweden-01'


def test_server_face_uses_the_node_picture():
    node = Node(
        name='Sweden-01',
        clash_name='Sweden-01',
        panel_url='https://203.0.113.10:2053/x',
        flag='se',
    )
    face = server_faces([node])
    shown = face('🇸🇪 Sweden-01 | yahoo')
    assert shown['flag'] == '/static/flags/se.png'
    assert shown['title'] == 'Швеция'
    assert shown['name'] == 'Sweden-01 | yahoo'
    assert '🇸🇪' not in shown['name']
    plain = face('Sweden-01 | 443')
    assert plain['flag'] == '/static/flags/se.png'
    assert plain['name'] == 'Sweden-01 | 443'
    unknown = server_faces([])('🇫🇮 Finland')
    assert unknown['flag'] == '/static/flags/fi.png'
    assert unknown['name'] == 'Finland'


def test_percentile_is_the_middle():
    assert percentile([100, 400, 200], 0.5) == 200
    assert percentile([], 0.5) is None


def test_a_report_lands_on_the_node_and_a_repeat_within_the_gap_does_not():
    _recent.clear()
    engine = _memory()
    now = datetime(2026, 11, 16, 18, tzinfo=timezone.utc)
    with Session(engine) as session:
        _seed(session)
        body = {
            'app_version': '1.1.1',
            'platform': 'windows',
            'exit_server': '🇸🇪 Sweden-01',
            'servers': [
                {
                    'server': '🇸🇪 Sweden-01',
                    'median_ms': 640,
                    'ok': 1,
                    'failed': 3,
                    'reason': 'handshake',
                    'at': now.isoformat(),
                }
            ],
        }
        assert ingest_report(session, 'tok', body, now) == 'ok'
        assert ingest_report(session, 'missing', body, now) == 'unknown'
        assert ingest_report(session, 'tok', body, now + timedelta(seconds=5)) == 'limited'
        rows = recent_nodes(session, now)
        sweden = next(item for item in rows if item['node'].name == 'Sweden-01')
        assert sweden['reports'] == 1
        assert sweden['fails'] == 0
        assert sweden['median'] == 640
        assert sweden['reasons']['handshake'] == 1


def test_a_dead_server_counts_as_a_failure():
    _recent.clear()
    engine = _memory()
    now = datetime(2026, 11, 16, 18, tzinfo=timezone.utc)
    with Session(engine) as session:
        _seed(session)
        assert (
            ingest_report(
                session,
                'tok',
                {
                    'servers': [
                        {
                            'server': 'Sweden-01',
                            'median_ms': None,
                            'ok': 0,
                            'failed': 4,
                            'reason': 'timeout',
                            'at': now.isoformat(),
                        }
                    ],
                },
                now,
            )
            == 'ok'
        )
        sweden = next(item for item in recent_nodes(session, now) if item['node'].name == 'Sweden-01')
        assert sweden['fails'] == 1
        assert sweden['median'] is None
        assert sweden['fail_rate'] == 100


def test_an_expired_client_is_refused():
    engine = _memory()
    now = datetime(2026, 11, 16, 18, tzinfo=timezone.utc)
    with Session(engine) as session:
        client, _node = _seed(session)
        client.expire_at = now - timedelta(days=1)
        session.add(client)
        session.commit()
        assert ingest_report(session, 'tok', {'servers': []}, now) == 'expired'


def test_old_hours_are_folded_and_then_dropped():
    engine = _memory()
    now = datetime(2026, 11, 16, 18, tzinfo=timezone.utc)
    with Session(engine) as session:
        _client, node = _seed(session)
        session.add(
            NodePingHour(
                node_id=node.id,
                hour=now - timedelta(days=20),
                reports=4,
                fails=1,
                samples_json=json.dumps([100, 300, 500]),
            )
        )
        session.add(
            NodePingHour(
                node_id=node.id,
                hour=now - timedelta(days=100),
                reports=1,
                samples_json='[10]',
            )
        )
        session.commit()
        purge_old_ping_hours(session, now)
        left = list(session.exec(select(NodePingHour)).all())
        assert len(left) == 1
        assert left[0].rolled is True
        assert json.loads(left[0].samples_json) == [300]


def test_http_report_uses_the_subscription_token():
    _recent.clear()
    engine = _memory()

    def _session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session
    try:
        with Session(engine) as session:
            _seed(session)
        client = TestClient(app)
        response = client.post(
            '/sub/tok/report',
            json={
                'app_version': '1.1.1',
                'platform': 'windows',
                'exit_server': 'Sweden-01',
                'servers': [
                    {
                        'server': 'Sweden-01',
                        'median_ms': 180,
                        'ok': 4,
                        'failed': 0,
                        'reason': '',
                        'at': '2026-11-16T18:00:00+00:00',
                    }
                ],
            },
        )
        assert response.status_code == 204
        with Session(engine) as session:
            rows = recent_nodes(session, datetime(2026, 11, 16, 18, 30, tzinfo=timezone.utc))
            assert rows[0]['median'] == 180
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_node_reporters_keep_status_and_time_for_each_tunnel():
    _recent.clear()
    engine = _memory()
    now = datetime(2026, 11, 16, 18, tzinfo=timezone.utc)
    with Session(engine) as session:
        office, node = _seed(session)
        home = Client(name='Дом', slug='home', uuid='u-2', sub_token='tok-2', enable=True)
        session.add(home)
        session.commit()
        assert (
            ingest_report(
                session,
                'tok',
                {
                    'app_version': '1.1.1',
                    'platform': 'windows',
                    'exit_server': '🇸🇪 Sweden-01',
                    'servers': [
                        {
                            'server': '🇸🇪 Sweden-01',
                            'median_ms': 640,
                            'ok': 1,
                            'failed': 3,
                            'reason': 'handshake',
                            'at': now.isoformat(),
                        },
                        {
                            'server': '🇸🇪 Sweden-01 | yahoo',
                            'median_ms': 200,
                            'ok': 4,
                            'failed': 0,
                            'reason': '',
                            'at': now.isoformat(),
                        },
                    ],
                },
                now,
            )
            == 'ok'
        )
        assert (
            ingest_report(
                session,
                'tok-2',
                {
                    'platform': 'android',
                    'servers': [
                        {
                            'server': 'Sweden-01',
                            'median_ms': None,
                            'ok': 0,
                            'failed': 4,
                            'reason': 'timeout',
                            'at': (now + timedelta(hours=1)).isoformat(),
                        }
                    ],
                },
                now + timedelta(hours=1),
            )
            == 'ok'
        )
        rows = node_reporters(session, node.id)
        assert [(row['client'].name, row['status']['key']) for row in rows] == [
            ('Дом', 'down:timeout'),
            ('Офис', 'partial:handshake'),
            ('Офис', 'ok'),
        ]
        home_row = rows[0]
        assert home_row['status']['label'] == 'долгий ответ'
        assert home_row['median'] is None
        assert home_row['failed'] == 4
        assert as_moscow(home_row['measured']) == '16.11 22:00'
        office_row = next(row for row in rows if row['status']['key'] == 'partial:handshake')
        assert office_row['ok'] == 1
        assert office_row['median'] == 640
        assert office_row['exit_here'] is True
        assert office_row['face']['name'] == 'Sweden-01'
        buckets = reporter_buckets(rows)
        assert [item['key'] for item in buckets] == ['ok', 'partial:handshake', 'down:timeout']
        assert buckets[0]['count'] == 1
        chart = client_server_chart(session, session.get(ClientPingReport, office.id))
        assert [item['median'] for item in chart['latency']] == [640, 200]
        assert chart['latency'][0]['latency_pct'] == 100
        assert chart['latency'][1]['latency_pct'] == max(4, round(100 * 200 / 640))
        assert chart['rows'][0]['href'] == f'/pings/node/{node.id}'
        assert chart['rows'][0]['rate'] == 25


def test_pings_pages_list_reporters_charts_and_sort_headers():
    _recent.clear()
    engine = _memory()

    def _session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session
    try:
        now = datetime(2026, 11, 16, 18, tzinfo=timezone.utc)
        with Session(engine) as session:
            client, node = _seed(session)
            assert (
                ingest_report(
                    session,
                    'tok',
                    {
                        'app_version': '1.1.1',
                        'platform': 'windows',
                        'exit_server': 'Sweden-01',
                        'servers': [
                            {
                                'server': '🇸🇪 Sweden-01',
                                'median_ms': 180,
                                'ok': 4,
                                'failed': 0,
                                'reason': '',
                                'at': now.isoformat(),
                            },
                            {
                                'server': '🇫🇮 Finland',
                                'median_ms': None,
                                'ok': 0,
                                'failed': 3,
                                'reason': 'handshake',
                                'at': now.isoformat(),
                            },
                        ],
                    },
                    now,
                )
                == 'ok'
            )
            node_id = node.id
            client_id = client.id
        http = TestClient(app)
        http.post('/login', data={'username': settings.admin_username, 'password': settings.admin_password})
        page = http.get('/pings')
        assert page.status_code == 200
        assert 'data-sortable' in page.text
        assert 'data-sort="fail"' in page.text
        assert 'data-sort="seen"' in page.text
        assert 'Офис' in page.text
        node_page = http.get(f'/pings/node/{node_id}')
        assert node_page.status_code == 200
        assert 'Кто прислал' in node_page.text
        assert 'Офис' in node_page.text
        assert 'доступен' in node_page.text
        assert 'data-status-filter="ok"' in node_page.text
        assert 'data-sort="measured"' in node_page.text
        client_page = http.get(f'/pings/client/{client_id}')
        assert client_page.status_code == 200
        assert 'ping-chart' in client_page.text
        assert 'Задержка' in client_page.text
        assert 'Успешные пробы' in client_page.text
        assert 'Finland' in client_page.text
        assert 'блок рукопожатия' in client_page.text
        assert '180 мс' in client_page.text
        assert 'data-sort="rate"' in client_page.text
    finally:
        app.dependency_overrides.pop(get_session, None)


def test_a_report_counts_open_tunnels_and_shows_moscow_time():
    report = ClientPingReport(
        client_id=1,
        servers_json=json.dumps(
            [
                {'server': 'Finland', 'ok': 1, 'failed': 0, 'median_ms': 40},
                {'server': 'Sweden', 'ok': 0, 'failed': 3, 'reason': 'handshake'},
            ]
        ),
    )
    assert availability_counts(report) == {'available': 1, 'unavailable': 1}
    assert as_moscow(datetime(2026, 11, 16, 21, 8, tzinfo=timezone.utc)) == '17.11 00:08'
