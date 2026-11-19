"""Приём сводок пинга от приложений и страница «С клиентов»."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response

from app.client_pings import (
    as_moscow,
    availability_counts,
    client_server_chart,
    epoch,
    ingest_report,
    node_day,
    node_reasons,
    node_reporters,
    reason_label,
    recent_clients,
    recent_nodes,
    reporter_buckets,
)
from app.deps import SessionDep
from app.models import Client, ClientPingReport, Node
from app.routers.ui import _ctx, templates

router = APIRouter()


def _admin(request: Request):
    from fastapi.responses import RedirectResponse

    from app.deps import request_authorized

    if not request_authorized(request):
        return RedirectResponse('/login', status_code=302)
    return None


@router.post('/clash/{token}/report', status_code=204)
@router.post('/sub/{token}/report', status_code=204)
async def accept_report(token: str, request: Request, session: SessionDep) -> Response:
    return await take_report(token, request, session)


async def take_report(token: str, request: Request, session: SessionDep) -> Response:
    try:
        payload = await request.json()
    except Exception as error:
        raise HTTPException(status_code=400, detail='bad report') from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail='bad report')
    result = ingest_report(session, token, payload)
    if result == 'unknown':
        raise HTTPException(status_code=404, detail='unknown subscription')
    if result == 'expired':
        raise HTTPException(status_code=403, detail='subscription expired')
    if result == 'bad':
        raise HTTPException(status_code=400, detail='bad report')
    if result == 'limited':
        raise HTTPException(status_code=429, detail='slow down')
    return Response(status_code=204)


@router.get('/pings', response_class=HTMLResponse)
def pings_page(request: Request, session: SessionDep):
    if (redir := _admin(request)):
        return redir
    nodes = recent_nodes(session)
    clients = recent_clients(session)
    blocked = sum(1 for _, report in clients if availability_counts(report)['unavailable'])
    return templates.TemplateResponse(
        'pings.html',
        _ctx(
            request,
            page='pings',
            nodes=nodes,
            clients=clients,
            report_count=sum(item['reports'] for item in nodes),
            client_count=len(clients),
            blocked=blocked,
            counts=availability_counts,
            as_moscow=as_moscow,
            epoch=epoch,
            reason_label=reason_label,
        ),
    )


@router.get('/pings/node/{node_id}', response_class=HTMLResponse)
def ping_node_page(request: Request, node_id: int, session: SessionDep):
    if (redir := _admin(request)):
        return redir
    node = session.get(Node, node_id)
    if node is None:
        raise HTTPException(status_code=404, detail='unknown node')
    series = node_day(session, node_id)
    peak = max((item['median'] or 0) for item in series) or 1
    reasons = [(reason_label(key), count) for key, count in node_reasons(session, node_id)]
    median = next((item['median'] for item in reversed(series) if item['median'] is not None), None)
    reporters = node_reporters(session, node_id)
    return templates.TemplateResponse(
        'pings_node.html',
        _ctx(
            request,
            page='pings',
            node=node,
            series=series,
            peak=peak,
            reasons=reasons,
            median=median,
            reporters=reporters,
            buckets=reporter_buckets(reporters),
            as_moscow=as_moscow,
        ),
    )


@router.get('/pings/client/{client_id}', response_class=HTMLResponse)
def ping_client_page(request: Request, client_id: int, session: SessionDep):
    if (redir := _admin(request)):
        return redir
    client = session.get(Client, client_id)
    report = session.get(ClientPingReport, client_id)
    if client is None or report is None:
        raise HTTPException(status_code=404, detail='unknown client')
    return templates.TemplateResponse(
        'pings_client.html',
        _ctx(
            request,
            page='pings',
            client=client,
            report=report,
            chart=client_server_chart(session, report),
            counts=availability_counts(report),
            as_moscow=as_moscow,
        ),
    )
