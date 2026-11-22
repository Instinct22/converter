from sqlmodel import Session, SQLModel, create_engine

from app.exporters import apply_exporter
from app.models import Node


def test_agent_uses_existing_receiver_and_requires_delivery_marker():
    engine = create_engine('sqlite://')
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        receiver = Node(name='Grafana', panel_url='https://monitor.example',
                        install_kind='grafana', install_state='done',
                        install_log='Токен записи: test-token')
        node = Node(name='VPN', panel_url='', public_host='192.0.2.1')
        session.add_all([receiver, node])
        session.commit()

        def install(host, script):
            assert host == '192.0.2.1'
            assert '-remoteWrite.url=https://monitor.example/api/v1/write' in script
            assert '--web.listen-address=127.0.0.1:9100' in script
            assert 'instance: "192.0.2.1"' in script
            return 0, 'EXPORTER_READY=1'

        apply_exporter(session, node.id, runner=install)
        assert node.exporter_state == 'done'
        apply_exporter(session, node.id, runner=lambda *_: (1, 'EXPORTER_ERROR=timeout'))
        assert node.exporter_state == 'failed'
        assert node.exporter_note == 'timeout'
