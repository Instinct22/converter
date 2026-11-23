from datetime import timezone

from apscheduler.events import EVENT_JOB_MAX_INSTANCES, EVENT_JOB_MISSED
from apscheduler.schedulers.background import BackgroundScheduler
from sqlmodel import Session, select

from app.activity import prune_history, tracked
from app.client_pings import purge_old_ping_hours
from app.database import engine
from app.models import Client, MasterOperation, Node, utcnow
from app.overview import aggregate_client_usage, probe_nodes, remember_last_online, store_probe
from app.provision import disable_expired
from app.site_traffic import ingest_access_log
from app.reachability import inbound_ports, probe_nodes_rf, store as store_rf_view

scheduler = BackgroundScheduler()


def _missed(event) -> None:
    job = scheduler.get_job(event.job_id)
    times = getattr(event, 'scheduled_run_times', None) or [event.scheduled_run_time]
    message = ('Предыдущий запуск ещё выполнялся' if event.code == EVENT_JOB_MAX_INSTANCES
               else 'Планировщик пропустил время запуска')
    with Session(engine) as session:
        session.add(MasterOperation(source='scheduler', title=job.name if job else event.job_id,
                                    state='warning', started_at=times[0].astimezone(timezone.utc),
                                    finished_at=utcnow(), detail=message))
        session.commit()


scheduler.add_listener(_missed, EVENT_JOB_MISSED | EVENT_JOB_MAX_INSTANCES)


@tracked('Опрос флота и проверка сроков доступа', 'scheduler')
def _job() -> dict:
    with Session(engine) as session:
        purge_old_ping_hours(session)
        expiry_steps = []
        expired = disable_expired(session, expiry_steps)
        nodes = session.exec(select(Node).where(Node.enabled.is_(True))).all()
        from app.fleet_metrics import save_presence
        probes = probe_nodes(nodes, refresh_versions=True)
        save_presence(nodes, probes)
        failures = []
        for node in nodes:
            probe = probes.get(node.id or 0) or {}
            if probe.get('online'):
                node.last_error = ''
            elif probe.get('error'):
                node.last_error = str(probe.get('error'))[:500]
            store_probe(node, probe)
            for issue in (probe.get('error'), node.panel_check_error, node.xray_check_error):
                if issue:
                    failures.append(f'{node.name}: {issue}')
            session.add(node)
        for client in session.exec(select(Client)):
            usage = aggregate_client_usage(client, nodes, probes)
            remember_last_online(session, client, usage['last_online'])
        prune_history(session)
        session.commit()
        summary = f'Проверено нод: {len(nodes)}. Отключено по сроку: {expired}.'
        return {'ok': not failures, 'logs': [summary, *failures, *expiry_steps]}


@tracked('Доступность нод из РФ', 'scheduler')
def _rf_job():
    with Session(engine) as session:
        return _refresh_rf(session, session.exec(select(Node).where(Node.enabled.is_(True))).all())


def _refresh_rf(session: Session, nodes: list[Node]) -> dict:
    """Лампочка «доступен из РФ» обновляется вместе с остальным обзором."""
    enabled = [node for node in nodes if node.id and node.enabled]
    ports_by_node = {
        int(node.id): inbound_ports(session, int(node.id)) for node in enabled
    }
    from app.fleet_metrics import save_snapshot
    views = probe_nodes_rf(enabled, ports_by_node)
    save_snapshot(enabled, views)
    for node in nodes:
        view = views.get(node.id or 0)
        if view:
            store_rf_view(node, view)
            session.add(node)
    failures = [f'{node.name}: {node.rf_note}' for node in enabled if not node.rf_ok]
    session.commit()
    return {'ok': not failures, 'logs': [f'Доступно нод: {len(enabled)-len(failures)} из {len(enabled)}', *failures]}


@tracked('Сбор статистики сайта', 'scheduler')
def _site_job() -> dict:
    with Session(engine) as session:
        count = ingest_access_log(session)
        return {'logs': [f'Обработано запросов: {count}']}


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(_job, 'interval', minutes=10, id='expire-clients', name='Опрос флота и проверка сроков доступа', replace_existing=True)
    scheduler.add_job(_rf_job, 'interval', minutes=1, id='rf-monitor', name='Доступность нод из РФ', coalesce=True, max_instances=1)
    scheduler.add_job(_site_job, 'interval', seconds=30, id='site-access', name='Сбор статистики сайта', replace_existing=True)
    scheduler.start()

