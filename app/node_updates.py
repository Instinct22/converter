"""Сверка версий и запуск обновлений через API панели."""
from __future__ import annotations

from datetime import timedelta, timezone
from typing import Any

from sqlalchemy import update
from sqlmodel import Session

from app.activity import worker_state
from app.models import Node, utcnow
from app.xui import XuiClient, XuiError, clean_version, version_equal, version_newer, versions_from_status

# Сколько ждём возврата ноды на целевую версию после запуска обновления, прежде чем
# пометить сбой. Обновление панели/ядра — это рестарт сервиса на ноде, обычно <1 мин.
UPDATE_TIMEOUT_MINUTES = 15


def _latest_xray(versions: list[str]) -> str:
    best = ''
    for v in versions:
        if not v:
            continue
        if not best or version_newer(v, best):
            best = v
    return best


def read_updates(xui: XuiClient) -> dict[str, str]:
    info = {'panel_current': '', 'panel_latest': '', 'xray_latest': '',
            'panel_error': '', 'xray_error': ''}
    try:
        panel = xui.get_panel_update_info()
        info['panel_current'] = clean_version(panel.get('currentVersion'))
        info['panel_latest'] = clean_version(panel.get('latestVersion'))
        if not info['panel_latest']:
            info['panel_error'] = 'Панель не сообщила доступную версию 3x-ui'
    except XuiError as exc:
        info['panel_error'] = str(exc)
        # A timeout while the panel checks GitHub does not rule out its cached Xray list.
        xui.unreachable = False
    try:
        info['xray_latest'] = _latest_xray(xui.get_xray_versions())
        if not info['xray_latest']:
            info['xray_error'] = 'Панель не сообщила доступные версии Xray'
    except XuiError as exc:
        info['xray_error'] = str(exc)
    return info


def store_updates(node: Node, info: dict) -> None:
    if info['panel_current']:
        node.xui_version = info['panel_current']
        node.version_checked_at = utcnow()
    node.panel_latest_version = info['panel_latest']
    node.xray_latest_version = info['xray_latest']
    node.panel_check_error = info['panel_error']
    node.xray_check_error = info['xray_error']
    node.update_checked_at = utcnow()


def check_updates(node: Node) -> dict[str, Any]:
    with XuiClient(node) as xui:
        try:
            panel, core = versions_from_status(xui.server_status())
        except XuiError:
            panel, core = '', ''
        info = read_updates(xui)
    panel = info['panel_current'] or panel
    if panel or core:
        node.xui_version = panel or node.xui_version
        node.xray_version = core or node.xray_version
        node.version_checked_at = utcnow()
    store_updates(node, info)
    return {
        **info, 'panel_current': panel, 'xray_current': core,
        'panel_differs': bool(panel and version_newer(info['panel_latest'], panel)),
        'xray_differs': bool(core and version_newer(info['xray_latest'], core)),
    }


def start_update(session: Session, node: Node, kind: str) -> dict[str, Any]:
    """Запустить обновление панели/ядра через API панели.

    Ставим update_state='running' + целевую версию; фактический успех разрешает
    reconcile_update по мере снятия версий обзором/планировщиком. Никаких фоновых
    потоков и откатa.
    """
    if kind not in ('panel', 'xray'):
        return {'ok': False, 'message': 'неизвестный тип обновления'}
    if not node.enabled:
        return {'ok': False, 'message': 'нода выключена и не в подписке'}
    if (node.update_state or '') == 'running':
        return {'ok': False, 'message': 'обновление уже выполняется'}

    info = check_updates(node)
    session.commit()
    if info[kind + '_error']:
        return {'ok': False, 'message': info[kind + '_error']}
    current = info[kind + '_current']
    if not current:
        return {'ok': False, 'message': 'Панель не сообщила установленную версию'}
    if not info[kind + '_differs']:
        return {'ok': False, 'message': 'Уже установлена актуальная версия'}
    target = info[kind + '_latest']

    # Reserve the node before sending the restart, including concurrent requests.
    started = utcnow()
    claimed = session.execute(update(Node).where(
        Node.id == node.id, Node.update_state != 'running', Node.enabled.is_(True)
    ).values(update_state='running', update_kind=kind, update_target_version=target,
             update_started_at=started))
    if claimed.rowcount:
        worker_state(session, node, 'update', 'Обновление ' + ('3x-ui' if kind == 'panel' else 'Xray'),
                     'running', f'{current} → {target}')
    session.commit()
    if not claimed.rowcount:
        return {'ok': False, 'message': 'Нода отключена или обновление уже запущено'}
    try:
        with XuiClient(node) as xui:
            if kind == 'panel':
                xui.update_panel()
            else:
                xui.install_xray(target)
    except XuiError as exc:
        worker_state(session, node, 'update', 'Обновление компонента', 'error', str(exc))
        _clear_update_state(node)
        session.commit()
        # Панель отказала — статус НЕ портим: стрелка ↑ остаётся, можно повторить.
        return {'ok': False, 'message': f'не удалось запустить обновление: {exc}'}

    return {
        'ok': True,
        'state': 'running',
        'kind': kind,
        'from': current,
        'to': target,
    }


def reconcile_update(node: Node, online: bool) -> None:
    """Подтвердить установленную версию или завершить ожидание по таймауту."""
    state = node.update_state or ''
    if not state:
        return
    kind = node.update_kind or ''
    current = (node.xui_version or '') if kind == 'panel' else (node.xray_version or '')
    target = node.update_target_version or ''

    if state == 'running':
        if current and target and (version_equal(current, target) or version_newer(current, target)):
            session = Session.object_session(node)
            if session:
                worker_state(session, node, 'update', 'Обновление компонента', 'ok', f'Установлена версия {current}')
            _clear_update_state(node)
            return
        started = node.update_started_at
        if started is not None and started.tzinfo is None:
            # SQLite отдаёт datetime без tzinfo — приводим к UTC для корректного вычитания.
            started = started.replace(tzinfo=timezone.utc)
        if started and (utcnow() - started) > timedelta(minutes=UPDATE_TIMEOUT_MINUTES):
            session = Session.object_session(node)
            if session:
                worker_state(session, node, 'update', 'Обновление компонента', 'error', f'Нода не подтвердила версию {target} за {UPDATE_TIMEOUT_MINUTES} минут')
            node.update_state = 'failed'
        return

    if state == 'failed' and online:
        _clear_update_state(node)


def _clear_update_state(node: Node) -> None:
    node.update_state = ''
    node.update_kind = ''
    node.update_target_version = ''
    node.update_started_at = None

