"""Persistent history of Master operations. Store summaries, never request payloads."""
from datetime import timedelta
from functools import wraps
from inspect import signature
import re

from fastapi import HTTPException
from sqlalchemy import delete, update
from sqlmodel import Session, select

from app import database
from app.models import Client, MasterOperation, Node, utcnow

STATES = {'running': 'В работе', 'ok': 'Успешно', 'warning': 'С замечаниями', 'error': 'Ошибка'}
SOURCES = {'master': 'Master', 'scheduler': 'Планировщик', 'admin': 'Панель / API', 'worker': 'Автоматизация'}


def diagnostic(value) -> str:
    lines = []
    for raw in str(value or '').splitlines():
        # Shell output and panel responses can contain entire credential documents.
        if re.match(r'^HTTP (401|403)\b', raw):
            lines.append('Панель отклонила авторизацию · ' + raw[:8])
            continue
        if re.search(r'парол|токен|password|secret|bearer|token|private.key|ssh-|MASTER_|GRAFANA_|[<>{}]', raw, re.I):
            continue
        line = re.sub(r'(?:https?|vless|ssh)://\S+', '[адрес]', raw)
        line = re.sub(r'[A-Za-z0-9_+/=-]{28,}', '[скрыто]', line)
        if line.strip():
            lines.append(line.strip()[:400])
    return '\n'.join(lines)[:2000]


def worker_state(session, node, task, title, state, detail):
    """Transitions share the caller's transaction with the underlying node state."""
    key = f'{task}/{node.id}'
    row = session.exec(select(MasterOperation).where(MasterOperation.active_key == key)).first()
    if row is None:
        row = MasterOperation(source='worker', title=title, target=node.name)
    row.state = state
    row.detail = diagnostic(detail)
    row.active_key = key if state == 'running' else None
    row.finished_at = None if state == 'running' else utcnow()
    session.add(row)


def master_started(session):
    now = utcnow()
    session.execute(update(MasterOperation).where(
        MasterOperation.state == 'running',
        # Component updates continue on the node and are reconciled after restart.
        (MasterOperation.active_key.is_(None) | ~MasterOperation.active_key.like('update/%'))
    ).values(state='error', detail='Master перезапустился до завершения операции',
             active_key=None, finished_at=now))
    session.add(MasterOperation(source='master', title='Запуск Master', state='ok',
                                started_at=now, finished_at=now, detail='База подготовлена к работе'))
    session.commit()


def prune_history(session):
    session.execute(delete(MasterOperation).where(
        MasterOperation.finished_at < utcnow() - timedelta(days=30)))


def outcome(result):
    if not isinstance(result, dict):
        return 'ok', ''
    if result.get('ok') is False:
        reason = result.get('message') or result.get('error') or '\n'.join(result.get('logs') or [])
        return 'error', diagnostic(reason) or 'Операция отклонена. Проверьте доступ и журнал сервиса.'
    results = result.get('results')
    if isinstance(results, list):
        errors = [f"{item.get('name') or 'Нода'}: {item['error']}" for item in results if item.get('error')]
        return ('warning' if errors else 'ok',
                diagnostic('\n'.join([f'Проверено нод: {len(results)}', *errors])))
    logs = result.get('logs') or []
    details = diagnostic('\n'.join(str(line) for line in logs))
    # Some existing operations report partial failures in their per-node steps.
    if re.search(r'ошиб|не удалось|не удалён|не навесился|не создан|нет (?:связи|входа|inbound)|не отвеч|failed|timeout|HTTP [45]\d\d|не выключить', details, re.I):
        return 'warning', details
    return 'ok', details


def tracked(title, source='admin'):
    def decorate(func):
        params = signature(func, eval_str=True)

        @wraps(func)
        def run(*args, **kwargs):
            arguments = params.bind(*args, **kwargs).arguments
            original = arguments.get('session')
            bind = original.get_bind() if original is not None else database.engine
            with Session(bind) as journal:
                target = 'Master'
                for key, model, label in [('node_id', Node, 'Нода'), ('client_id', Client, 'Клиент')]:
                    target_id = arguments.get(key) or getattr(arguments.get('body'), key, None)
                    if target_id:
                        obj = journal.get(model, target_id)
                        target = obj.name if obj else f'{label} №{target_id}'
                        break
                else:
                    target = getattr(arguments.get('body'), 'name', '') or target
                entry = MasterOperation(source=source, title=title, target=target)
                journal.add(entry)
                journal.commit()
                try:
                    result = func(*args, **kwargs)
                    entry.state, entry.detail = outcome(result)
                    return result
                except Exception as exc:
                    if original is not None:
                        original.rollback()
                    entry.state = 'error'
                    if isinstance(exc, HTTPException):
                        reason = diagnostic(exc.detail) or 'Проверьте параметры запроса и доступ к сервису'
                        entry.detail = f'HTTP {exc.status_code} · {reason}'
                        if isinstance(exc.detail, dict) and exc.detail.get('code') == 'confirm_ssh_host_key':
                            entry.state = 'warning'
                            entry.detail = 'Ожидается подтверждение отпечатка SSH'
                    else:
                        entry.detail = f'Сбой Master ({type(exc).__name__})'
                        if isinstance(exc, (TypeError, TimeoutError, ConnectionError, OSError)):
                            entry.detail += ' · ' + diagnostic(exc)
                    raise
                finally:
                    entry.finished_at = utcnow()
                    journal.add(entry)
                    journal.commit()
        run.__signature__ = params
        return run
    return decorate
