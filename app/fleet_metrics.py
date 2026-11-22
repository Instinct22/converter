"""Read-only агрегаты Master для vmagent на сервере мониторинга."""
import hashlib
import hmac
import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response
from sqlmodel import select

from app.client_pings import floor_hour, percentile
from app.deps import SessionDep
from app.exporters import grafana_target
from app.models import Node, NodePingHour

router = APIRouter()
snapshot = []
presence_snapshot = []


def save_presence(nodes, probes):
    global presence_snapshot
    lines = []
    for node in nodes:
        result = probes.get(node.id, {})
        if result.get('presence_valid'):
            labels = 'node=' + json.dumps(node.name, ensure_ascii=False)
            count = len(set(result['online_emails'] or []))
            lines.append(f'master_active_accounts{{{labels}}} {count}')
    lines.append(f'master_presence_checked_seconds {datetime.now(timezone.utc).timestamp()}')
    presence_snapshot = lines


def scrape_key(token):
    return hmac.new(token.encode(), b'master-fleet-scrape-v1', hashlib.sha256).hexdigest()


def save_snapshot(nodes, views):
    global snapshot
    lines = []
    for node in nodes:
        labels = 'node=' + json.dumps(node.name, ensure_ascii=False)
        for port in views.get(node.id, {}).get('ports', []):
            tags = labels + ',port="' + str(port['port']) + '"'
            lines.append(f'master_rf_tcp_success{{{tags}}} {int(port["ok"])}')
            if port['ok']:
                lines.append(f'master_rf_tcp_duration_ms{{{tags}}} {port["ms"]}')
    lines.append(f'master_rf_checked_seconds {datetime.now(timezone.utc).timestamp()}')
    snapshot = lines


@router.get('/monitoring/master.prom')
def metrics(request: Request, session: SessionDep):
    try:
        _, token = grafana_target(session)
    except ValueError:
        raise HTTPException(503)
    if not hmac.compare_digest(request.headers.get('Authorization', '').encode(),
                               ('Bearer ' + scrape_key(token)).encode()):
        raise HTTPException(401)
    lines = snapshot + presence_snapshot
    hour = floor_hour(datetime.now(timezone.utc))
    rows = session.exec(select(NodePingHour, Node).join(Node).where(NodePingHour.hour == hour)).all()
    for row, node in rows:
        labels = 'node=' + json.dumps(node.name, ensure_ascii=False)
        lines.append(f'master_client_reports_hour{{{labels}}} {row.reports}')
        lines.append(f'master_client_failures_hour{{{labels}}} {row.fails}')
        latency = percentile(json.loads(row.samples_json), .9)
        if latency is not None:
            lines.append(f'master_client_p90_ms{{{labels}}} {latency}')
    return Response(chr(10).join(lines) + chr(10), media_type='text/plain; version=0.0.4')
