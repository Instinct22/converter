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
    ingest_report,
    normalize_server,
    percentile,
    purge_old_ping_hours,
    recent_nodes,
    server_faces,
)
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
