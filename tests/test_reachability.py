import errno
import socket

from sqlmodel import Session, SQLModel, create_engine

from app.models import Node, NodeInbound
from app.reachability import (
    _reason,
    accepted_elsewhere,
    clean_ports,
    inbound_ports,
    node_host,
    probe_nodes_rf,
    probe_port,
    store,
)


def _engine():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    return engine


def _free_port() -> int:
    """Порт, который точно никем не слушается на loopback."""
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    listener.close()
    return port


def _listener_port() -> int:
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    return listener, listener.getsockname()[1]


def test_node_host_prefers_public_host_then_panel():
    public = Node(name='DE', panel_url='https://1.2.3.4:2053/xui', public_host='de.example.com')
    panel = Node(name='IT', panel_url='https://5.6.7.8:2053/xui')
    empty = Node(name='X', panel_url='')
    assert node_host(public) == 'de.example.com'
    assert node_host(panel) == '5.6.7.8'
    assert node_host(empty) == ''


def test_inbound_ports_only_published_and_nonzero():
    engine = _engine()
    with Session(engine) as session:
        node = Node(name='DE', panel_url='https://1.2.3.4:2053/xui', public_host='1.2.3.4')
        session.add(node)
        session.commit()
        session.refresh(node)
        session.add_all(
            [
                NodeInbound(node_id=node.id, xui_inbound_id=1, port=443, use_in_sub=True),
                NodeInbound(node_id=node.id, xui_inbound_id=2, port=8443, use_in_sub=True),
                NodeInbound(node_id=node.id, xui_inbound_id=3, port=2083, use_in_sub=False),
                NodeInbound(node_id=node.id, xui_inbound_id=4, port=0, use_in_sub=True),
            ]
        )
        session.commit()
        assert inbound_ports(session, node.id) == [443, 8443]
    assert clean_ports([8443, 443, 443, 0, -5]) == [443, 8443]


def test_probe_port_open_then_unreachable_on_loopback():
    listener, port = _listener_port()
    opened = probe_port('127.0.0.1', port, timeout=2.0)
    assert opened['ok'] is True
    assert opened['port'] == port
    assert opened['error'] == ''
    assert opened['ms'] >= 0
    listener.close()
    closed = probe_port('127.0.0.1', port, timeout=1.0)
    assert closed['ok'] is False
    # Формулировка зависит от стека: где-то RST («порт закрыт»), где-то тихий дроп (TUN, файрвол).
    assert closed['error'] != ''


def test_reason_texts_are_human_readable():
    assert _reason(OSError(errno.ECONNREFUSED, '')) == 'порт закрыт'
    assert _reason(OSError(errno.EHOSTUNREACH, '')) == 'маршрут не найден'
    assert _reason(OSError(errno.ECONNRESET, '')) == 'соединение сброшено'
    assert _reason(OSError(errno.ETIMEDOUT, '')) == 'нет ответа'
    assert _reason(OSError()) == 'не отвечает'
    assert 'странно' in _reason(OSError(42, 'странно'))


def test_probe_nodes_rf_needs_every_published_port():
    listener, open_port = _listener_port()
    dead_port = _free_port()
    try:
        engine = _engine()
        with Session(engine) as session:
            good = Node(name='RU', panel_url='https://127.0.0.1:2053/xui', public_host='127.0.0.1')
            bad = Node(name='DE', panel_url='https://127.0.0.1:2053/xui', public_host='127.0.0.1')
            empty = Node(name='NONE', panel_url='https://127.0.0.1:2053/xui', public_host='127.0.0.1')
            session.add_all([good, bad, empty])
            session.commit()
            nodes = [good, bad, empty]
            views = probe_nodes_rf(
                nodes,
                {
                    good.id: [open_port, dead_port],
                    bad.id: [dead_port],
                    empty.id: [],
                },
                timeout=1.0,
            )
            assert views[good.id]['ok'] is False
            assert [row['port'] for row in views[good.id]['ports']] == sorted([open_port, dead_port])
            assert views[bad.id]['ok'] is False
            assert str(dead_port) in views[bad.id]['note']
            assert 'нет' in views[bad.id]['note']
            assert views[empty.id]['ok'] is False
            assert views[empty.id]['note'] == 'нет портов в подписке'
    finally:
        listener.close()


def test_an_instant_accept_is_not_the_server(monkeypatch):
    def fake(host, port, timeout=4.0):
        if port == 2053:
            return {'port': port, 'ok': True, 'ms': 15, 'error': ''}
        return {'port': port, 'ok': True, 'ms': 0, 'error': ''}

    monkeypatch.setattr('app.reachability.probe_port', fake)
    node = Node(
        id=1,
        name='LV',
        panel_url='https://203.0.113.8:2053/xui',
        public_host='203.0.113.8',
        ssh_port=22,
    )
    view = probe_nodes_rf([node], {1: [443]})[1]
    assert view['ok'] is False
    assert 'принят не сервером' in view['note']
    assert accepted_elsewhere(0, 15) is True
    assert accepted_elsewhere(14, 15) is False
    assert accepted_elsewhere(0, 1) is False


def test_a_disabled_node_is_not_probed(monkeypatch):
    def fail(host, port, timeout=4.0):
        raise AssertionError('disabled node must not be dialed')

    monkeypatch.setattr('app.reachability.probe_port', fail)
    node = Node(
        id=2,
        name='IT',
        panel_url='https://203.0.113.9:2053/xui',
        public_host='203.0.113.9',
        enabled=False,
    )
    assert probe_nodes_rf([node], {2: [443]}) == {}


def test_store_remembers_the_probe():
    listener, port = _listener_port()
    try:
        engine = _engine()
        with Session(engine) as session:
            node = Node(name='DE', panel_url='https://127.0.0.1:2053/xui', public_host='127.0.0.1')
            session.add(node)
            session.commit()
            view = probe_nodes_rf([node], {node.id: [port]}, timeout=2.0)[node.id]
            store(node, view)
            assert node.rf_ok is True
            assert node.rf_checked_at is not None
            assert str(port) in node.rf_note
    finally:
        listener.close()
