"""Read-only снятие latest-версий + ручное обновление панели 3x-ui и ядра Xray по API.

Обновление запускается из UI по клику на жёлтую стрелку ↑ (после окна подтверждения)
и выполняется в фоновом потоке: мастер дёргает API панели (updatePanel / installXray),
затем ждёт возврата ноды в строй до UPDATE_TIMEOUT секунд. Если нода за это время не
поднялась — помечает update_state='failed': в UI против версии загорается красный «!»,
и пользователь может подтвердить откат (для ядра ставим прежнюю версию) или отменить,
оставив ошибку для ручного разбирательства на самой ноде.

3x-ui не умеет понижать версию панели по API, поэтому автоматический откат доступен
только для ядра Xray; для панели при сбое ошибка остаётся — инженер правит ноду сам.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any

from sqlmodel import Session

from app.models import Node, utcnow
from app.xui import (
    XuiClient,
    XuiError,
    clean_version,
    version_equal,
    version_newer,
    versions_from_status,
)

# Сколько секунд ждём возврата ноды после обновления (панель/ядро). По умолчанию 3 минуты;
# для локальной проверки можно укоротить переменной окружения XUI_UPDATE_TIMEOUT_S.
DEFAULT_UPDATE_TIMEOUT = 180.0
POLL_INTERVAL = 5.0


def _update_timeout() -> float:
    raw = (os.environ.get('XUI_UPDATE_TIMEOUT_S') or '').strip()
    try:
        val = float(raw)
    except ValueError:
        return DEFAULT_UPDATE_TIMEOUT
    return val if val > 0 else DEFAULT_UPDATE_TIMEOUT


def check_updates(node: Node) -> dict[str, Any]:
    """Опросить ноду: какие версии доступны. Сохранить latest в Node.

    current берём из xui_version/xray_version (сняты опросом обзора), а для панели
    доверяем currentVersion из getPanelUpdateInfo, если он есть.
    """
    with XuiClient(node, timeout=15.0) as xui:
        info = xui.get_panel_update_info()
        versions = xui.get_xray_versions()
    panel_current = clean_version(info.get('currentVersion')) or (node.xui_version or '')
    panel_latest = clean_version(info.get('latestVersion'))
    xray_current = node.xray_version or ''
    xray_latest = versions[0] if versions else ''
    node.panel_latest_version = panel_latest or node.panel_latest_version or ''
    node.xray_latest_version = xray_latest or node.xray_latest_version or ''
    node.update_checked_at = utcnow()
    return {
        'panel_current': panel_current,
        'panel_latest': panel_latest,
        'xray_current': xray_current,
        'xray_latest': xray_latest,
        'panel_differs': bool(panel_latest and panel_current and version_newer(panel_latest, panel_current)),
        'xray_differs': bool(xray_latest and xray_current and version_newer(xray_latest, xray_current)),
    }


def _panel_back(node: Node, target: str) -> tuple[bool, str]:
    """Панель снова отвечает и (если отдаёт версию) не старше target."""
    deadline = time.monotonic() + _update_timeout()
    last = 'нет ответа'
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            with XuiClient(node, timeout=8.0) as xui:
                st = xui.server_status()
        except XuiError as exc:
            last = str(exc)
            continue
        pv = clean_version((st or {}).get('panelVersion'))
        if not pv:
            return True, ''  # панель отвечает, но версию не отдаёт — считаем, что вернулась
        if not target or not version_newer(target, pv):
            return True, ''
        last = f'панель ещё на {pv}'
    return False, last


def _xray_back(node: Node, target: str) -> tuple[bool, str]:
    """Ядро поднято (running) и имеет версию target."""
    deadline = time.monotonic() + _update_timeout()
    last = 'нет ответа'
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            with XuiClient(node, timeout=8.0) as xui:
                st = xui.server_status()
        except XuiError as exc:
            last = str(exc)
            continue
        _panel_v, xray_v = versions_from_status(st)
        state = str(((st or {}).get('xray') or {}).get('state') or '').lower()
        if xray_v and (not target or version_equal(xray_v, target)) and state in ('', 'running'):
            return True, ''
        last = f'ядро {xray_v or "?"} ({state or "?"})'
    return False, last


def _set_state(session: Session, node: Node, **fields: Any) -> None:
    for key, value in fields.items():
        setattr(node, key, value)
    node.update_checked_at = utcnow()
    session.add(node)
    session.commit()


def _finalize_ok(session: Session, node: Node, kind: str, target: str) -> None:
    if not target:
        return
    if kind == 'panel':
        node.xui_version = target
    else:
        node.xray_version = target
    _set_state(
        session, node,
        update_state='', update_kind='', update_prev_version='', update_target_version='',
    )


def _wait_and_finish(node_id: int, kind: str, target: str) -> None:
    """Фон-поток: ждём возврата ноды, затем success (обновили версию) либо failed."""
    from app.database import engine

    with Session(engine) as session:
        node = session.get(Node, node_id)
        if node is None:
            return
        try:
            ok, _msg = _panel_back(node, target) if kind == 'panel' else _xray_back(node, target)
        except Exception:
            ok = False
        if ok:
            _finalize_ok(session, node, kind, target)
        else:
            _set_state(session, node, update_state='failed')



def start_update(session: Session, node: Node, kind: str) -> dict[str, Any]:
    """Запускает обновление панели/ядра через API панели в фоновом потоке.

    kind: 'panel' | 'xray'. Возвращает {ok, state, kind, from, to, message}.
    """
    if kind not in ('panel', 'xray'):
        return {'ok': False, 'message': 'неизвестный тип обновления'}
    if (node.update_state or '') == 'running':
        return {'ok': False, 'message': 'обновление уже выполняется'}
    if not node.enabled:
        return {'ok': False, 'message': 'нода выключена и не в подписке'}
    try:
        info = check_updates(node)
    except XuiError as exc:
        return {'ok': False, 'message': f'нода не отвечает: {exc}'}
    if kind == 'panel':
        if not info['panel_differs']:
            return {'ok': False, 'message': 'панель уже актуальна'}
        prev, target = (info['panel_current'] or node.xui_version or ''), info['panel_latest']
    else:
        if not info['xray_differs']:
            return {'ok': False, 'message': 'ядро уже актуально'}
        prev, target = (info['xray_current'] or node.xray_version or ''), info['xray_latest']
    try:
        with XuiClient(node, timeout=20.0) as xui:
            if kind == 'panel':
                xui.update_panel()
            else:
                xui.install_xray(target)
    except XuiError as exc:
        _set_state(
            session, node,
            update_state='failed', update_kind=kind,
            update_prev_version=prev, update_target_version=target,
        )
        return {'ok': False, 'state': 'failed', 'kind': kind, 'message': f'панель отклонила обновление: {exc}'}
    _set_state(
        session, node,
        update_state='running', update_kind=kind,
        update_prev_version=prev, update_target_version=target,
    )
    threading.Thread(
        target=_wait_and_finish, args=(node.id or 0, kind, target),
        name=f'node-update-{node.id}-{kind}', daemon=True,
    ).start()
    return {'ok': True, 'state': 'running', 'kind': kind, 'from': prev, 'to': target}


def _rollback_finish(node_id: int) -> None:
    """Фон-поток отката: ждём возврата ноды на прежней версии, затем success либо failed."""
    from app.database import engine

    with Session(engine) as session:
        node = session.get(Node, node_id)
        if node is None:
            return
        kind = node.update_kind or 'xray'
        prev = node.update_prev_version
        try:
            ok, _msg = _panel_back(node, prev) if kind == 'panel' else _xray_back(node, prev)
        except Exception:
            ok = False
        if ok:
            _finalize_ok(session, node, kind, prev)
        else:
            _set_state(session, node, update_state='failed')


def start_rollback(session: Session, node: Node) -> dict[str, Any]:
    """Откат после сбоя: для ядра ставим прежнюю версию (installXray(prev)).

    Для панели автоматический откат невозможен (3x-ui не понижает версию по API) —
    возвращаем подсказку, ошибка остаётся для ручного разбирательства на ноде.
    """
    if (node.update_state or '') != 'failed':
        return {'ok': False, 'message': 'нечего откатывать'}
    kind = node.update_kind or ''
    prev = node.update_prev_version or ''
    if kind == 'panel':
        return {
            'ok': False, 'state': 'failed', 'kind': 'panel',
            'message': 'автоматический откат панели недоступен — проверьте ноду вручную',
        }
    if not prev:
        return {'ok': False, 'state': 'failed', 'message': 'нет прежней версии для отката'}
    try:
        with XuiClient(node, timeout=20.0) as xui:
            xui.install_xray(prev)
    except XuiError as exc:
        return {'ok': False, 'state': 'failed', 'kind': kind, 'message': f'откат не запущен: {exc}'}
    _set_state(session, node, update_state='running', update_target_version=prev)
    threading.Thread(
        target=_rollback_finish, args=(node.id or 0,),
        name=f'node-rollback-{node.id}', daemon=True,
    ).start()
    return {'ok': True, 'state': 'running', 'kind': kind, 'to': prev}

