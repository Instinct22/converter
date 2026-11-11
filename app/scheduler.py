from apscheduler.schedulers.background import BackgroundScheduler
from sqlmodel import Session, select

from app.database import engine
from app.models import Node
from app.overview import probe_nodes
from app.provision import disable_expired
from app.reachability import inbound_ports, probe_nodes_rf, store as store_rf_view

scheduler = BackgroundScheduler()


def _job() -> None:
    with Session(engine) as session:
        disable_expired(session)
        nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
        probes = probe_nodes(nodes)
        for node in nodes:
            probe = probes.get(node.id or 0) or {}
            if probe.get('online'):
                node.last_error = ''
            elif probe.get('error'):
                node.last_error = str(probe.get('error'))[:500]
            session.add(node)
        session.commit()
        _refresh_rf(session, nodes)


def _refresh_rf(session: Session, nodes: list[Node]) -> None:
    """Лампочка «доступен из РФ» обновляется вместе с остальным обзором."""
    enabled = [node for node in nodes if node.id and node.enabled]
    ports_by_node = {
        int(node.id): inbound_ports(session, int(node.id)) for node in enabled
    }
    views = probe_nodes_rf(enabled, ports_by_node)
    for node in nodes:
        view = views.get(node.id or 0)
        if view:
            store_rf_view(node, view)
            session.add(node)
    session.commit()


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(_job, 'interval', minutes=10, id='expire-clients', replace_existing=True)
    scheduler.start()
