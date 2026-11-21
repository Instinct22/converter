from apscheduler.schedulers.background import BackgroundScheduler
from sqlmodel import Session, select

from app.client_pings import purge_old_ping_hours
from app.database import engine
from app.models import Node
from app.node_updates import check_updates, reconcile_update
from app.overview import probe_nodes, store_versions
from app.provision import disable_expired
from app.site_traffic import ingest_access_log
from app.reachability import inbound_ports, probe_nodes_rf, store as store_rf_view
from app.xui import XuiError

scheduler = BackgroundScheduler()


def _job() -> None:
    with Session(engine) as session:
        purge_old_ping_hours(session)
        disable_expired(session)
        nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
        probes = probe_nodes(nodes)
        for node in nodes:
            probe = probes.get(node.id or 0) or {}
            if probe.get('online'):
                node.last_error = ''
            elif probe.get('error'):
                node.last_error = str(probe.get('error'))[:500]
            # Версии панели и ядра снимаются с того же ответа /server/status,
            # что и CPU/RAM: отдельного запроса на ноде они не требуют.
            store_versions(node, probe.get('status') or {})
            # Разрешаем статус обновления по фактической версии (без ложного «сбоя»).
            reconcile_update(node, bool(probe.get('online')))
            # Read-only: снимаем доступные (latest) версии панели и ядра, чтобы в
            # таблице нод против версии загорелась жёлтая стрелка ↑ (есть новее) либо
            # версия стала зелёной (актуально). Ничего не устанавливаем.
            try:
                check_updates(node)
            except XuiError:
                pass
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


def _site_job() -> None:
    with Session(engine) as session:
        ingest_access_log(session)


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(_job, 'interval', minutes=10, id='expire-clients', replace_existing=True)
    scheduler.add_job(_site_job, 'interval', seconds=30, id='site-access', replace_existing=True)
    scheduler.start()

