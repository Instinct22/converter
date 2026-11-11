from apscheduler.schedulers.background import BackgroundScheduler
from sqlmodel import Session, select

from app.database import engine
from app.models import Node
from app.overview import probe_nodes
from app.provision import disable_expired

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


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(_job, 'interval', minutes=10, id='expire-clients', replace_existing=True)
    scheduler.start()
