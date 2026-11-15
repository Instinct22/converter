"""Read-only снятие latest-версий + запуск обновления панели/ядра через API панели.

Откат НЕ поддерживается: 3x-ui не понижает версию панели по API, а переустановка
прежней версии ядра падает, когда старая версия уже выпала из списка релизов панели
(типичный случай сразу после обновления). Поэтому статус обновления разрешается по
ФАКТИЧЕСКОЙ версии ноды: обзор и планировщик каждый цикл снимают xui_version/
xray_version — если версия дошла до целевой (или новее), обновление засчитывается
успешным (зелёный текст), без ложного «сбоя». Красный «!» ставится только если нода
пропала надолго (offline по таймауту) и означает «проверьте ноду вручную».
"""
from __future__ import annotations

import logging
from datetime import timedelta, timezone
from typing import Any

from sqlmodel import Session

from app.models import Node, utcnow
from app.xui import XuiClient, XuiError, version_equal, version_newer

log = logging.getLogger(__name__)

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


def check_updates(node: Node) -> dict[str, Any]:
    """Опросить ноду: какие версии доступны. Сохранить latest в Node.

    Только чтение — ничего не устанавливаем. Нужен, чтобы в таблице нод против
    версии загорелась жёлтая стрелка ↑ (есть новее) либо версия стала зелёной.
    """
    with XuiClient(node) as xui:
        panel_info = xui.get_panel_update_info()
        xray_versions = xui.get_xray_versions()

    panel_current = str(panel_info.get('currentVersion') or '')
    panel_latest = str(panel_info.get('latestVersion') or '')
    xray_latest = _latest_xray(xray_versions)

    node.panel_latest_version = panel_latest
    node.xray_latest_version = xray_latest
    node.update_checked_at = utcnow()

    panel_differs = bool(panel_latest) and version_newer(panel_latest, node.xui_version or '')
    xray_differs = bool(xray_latest) and version_newer(xray_latest, node.xray_version or '')

    return {
        'panel_current': panel_current,
        'panel_latest': panel_latest,
        'xray_current': node.xray_version or '',
        'xray_latest': xray_latest,
        'panel_differs': panel_differs,
        'xray_differs': xray_differs,
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

    try:
        info = check_updates(node)
    except XuiError as exc:
        return {'ok': False, 'message': f'нода не отвечает: {exc}'}

    if kind == 'panel':
        if not info['panel_differs']:
            return {'ok': False, 'message': 'панель уже на актуальной версии'}
        target = info['panel_latest']
    else:
        if not info['xray_differs']:
            return {'ok': False, 'message': 'ядро уже на актуальной версии'}
        target = info['xray_latest']

    try:
        with XuiClient(node) as xui:
            if kind == 'panel':
                xui.update_panel()
            else:
                xui.install_xray(target)
    except XuiError as exc:
        # Панель отказала — статус НЕ портим: стрелка ↑ остаётся, можно повторить.
        return {'ok': False, 'message': f'не удалось запустить обновление: {exc}'}

    node.update_state = 'running'
    node.update_kind = kind
    node.update_target_version = target
    node.update_started_at = utcnow()
    session.add(node)
    session.commit()
    return {
        'ok': True,
        'state': 'running',
        'kind': kind,
        'from': node.xui_version if kind == 'panel' else node.xray_version,
        'to': target,
    }


def reconcile_update(node: Node, online: bool) -> None:
    """Разрешает статус running/failed по ФАКТИЧЕСКОЙ версии ноды.

    Вызывается из обзора/планировщика сразу после снятия свежих xui_version/
    xray_version. Правила:
      * running + версия дошла до целевой (или новее) → успех: статус снимаем,
        в UI версия станет зелёной (никакого ложного «сбоя»);
      * running + нода online, но на прежней версии → ждём (обновление идёт);
      * running + нода offline дольше таймаута → failed («проверьте ноду вручную»);
      * failed + нода снова online → статус снимаем: возвращаем стрелку ↑, чтобы
        можно было повторить обновление.
    """
    state = node.update_state or ''
    if not state:
        return
    kind = node.update_kind or ''
    current = (node.xui_version or '') if kind == 'panel' else (node.xray_version or '')
    target = node.update_target_version or ''

    if state == 'running':
        if current and target and (version_equal(current, target) or version_newer(current, target)):
            _clear_update_state(node)
            return
        started = node.update_started_at
        if started is not None and started.tzinfo is None:
            # SQLite отдаёт datetime без tzinfo — приводим к UTC для корректного вычитания.
            started = started.replace(tzinfo=timezone.utc)
        if (not online) and started and (utcnow() - started) > timedelta(minutes=UPDATE_TIMEOUT_MINUTES):
            node.update_state = 'failed'
        return

    if state == 'failed' and online:
        _clear_update_state(node)


def _clear_update_state(node: Node) -> None:
    node.update_state = ''
    node.update_kind = ''
    node.update_target_version = ''
    node.update_started_at = None

