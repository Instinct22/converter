"""Ручное обновление панелей 3x-ui и ядер Xray по API.

Два объекта обновления: панель (3x-ui) и ядро (Xray). Панель перезапускает только
веб-процесс — клиентов не рвёт. Ядро меняет бинарь Xray и перезапускает его — это
микро-reconnect клиентов; если новое ядро не поднялось, автоматически откатываемся
на прежнюю версию, чтобы нода осталась рабочей.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any

from sqlmodel import Session, select

from app.models import Node, UpdateNotification, utcnow
from app.xui import XuiClient, XuiError, clean_version, version_newer

# Средний таймаут возврата: и на панель, и на ядро.
STEP_TIMEOUT = 240.0
# С каким шагом поллим статус панели и пингуем ноду после обновления ядра.
POLL_INTERVAL = 10.0


@dataclass
class UpdateResult:
    node_id: int
    node_name: str
    ok: bool
    skipped: bool = False
    reason: str = ''
    message: str = ''
    panel_updated: bool = False
    xray_updated: bool = False
    rolled_back: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _notify(session: Session, node_name: str | None, message: str) -> UpdateNotification:
    note = UpdateNotification(node_name=node_name, message=message)
    session.add(note)
    session.commit()
    return note


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


def _update_panel_step(node: Node) -> tuple[bool, str]:
    """updatePanel → поллинг getUpdateStatus. Панель без пула: она не рвёт клиентов."""
    try:
        with XuiClient(node, timeout=20.0) as xui:
            run_id = xui.update_panel()
        node.update_run_id = run_id
    except XuiError as exc:
        return False, str(exc)
    deadline = time.monotonic() + STEP_TIMEOUT
    last_err = ''
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            with XuiClient(node, timeout=10.0) as xui:
                status = xui.get_update_status()
        except XuiError as exc:
            last_err = str(exc)
            continue
        state = str(status.get('state') or '').lower()
        if state == 'success':
            return True, ''
        if state == 'failed':
            return False, 'панель сообщила об ошибке обновления'
    return False, f'таймаут ожидания обновления панели ({last_err or "нет ответа"})'


def _wait_back(node: Node) -> tuple[bool, str]:
    """Пингуем ноду (status), пока не вернётся в строй, максимум STEP_TIMEOUT."""
    deadline = time.monotonic() + STEP_TIMEOUT
    last_err = ''
    while time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL)
        try:
            with XuiClient(node, timeout=8.0) as xui:
                xui.server_status()
            return True, ''
        except XuiError as exc:
            last_err = str(exc)
    return False, f'нода не вернулась за {int(STEP_TIMEOUT)} сек ({last_err or "нет ответа"})'


def _xray_running(node: Node) -> bool:
    """Ядро реально работает после обновления? Панель могла подняться, а Xray — нет."""
    try:
        with XuiClient(node, timeout=10.0) as xui:
            obj = xui.server_status()
    except XuiError:
        return False
    xray = obj.get('xray') if isinstance(obj.get('xray'), dict) else {}
    state = str(xray.get('state') or '').lower()
    if not state:
        # Старая панель состояние не отдаёт: раз отвечает — считаем ядро живым.
        return True
    return state == 'running'


def _update_xray_step(node: Node, version: str) -> tuple[bool, str]:
    try:
        with XuiClient(node, timeout=30.0) as xui:
            xui.install_xray(version)
    except XuiError as exc:
        return False, str(exc)
    ok, msg = _wait_back(node)
    if not ok:
        return False, msg
    if not _xray_running(node):
        return False, 'ядро не запустилось после обновления'
    return True, ''


def _rollback_xray(node: Node, prev_version: str) -> tuple[bool, str]:
    """Вернуть ядро на прежнюю версию после неудачного обновления.

    Ставим installXray на прежнюю версию и снова ждём возврата + работающего ядра.
    Если прежняя версия неизвестна — откат невозможен.
    """
    if not prev_version:
        return False, 'прежняя версия ядра неизвестна'
    try:
        with XuiClient(node, timeout=30.0) as xui:
            xui.install_xray(prev_version)
    except XuiError as exc:
        return False, str(exc)
    ok, msg = _wait_back(node)
    if not ok:
        return False, msg
    if not _xray_running(node):
        return False, 'ядро не запустилось после отката'
    return True, ''



def perform_update(session: Session, node: Node, *, kind: str = 'both') -> UpdateResult:
    """Обновить одну ноду вручную. kind: 'panel' | 'xray' | 'both'.

    Панель и ядро — отдельные сущности: kind='panel' трогает только веб-процесс
    панели, kind='xray' — только бинарь Xray, kind='both' — панель, затем ядро.

    Панель обновляем смело (не рвёт клиентов). Ядро перезапускается; если новое
    ядро не поднялось — автоматически откатываемся на прежнюю версию. Каждый
    пропуск/сбой/успех фиксируется уведомлением (UpdateNotification), чтобы зона
    «Уведомления» в ручном режиме не оставалась пустой.
    """
    name = node.name
    if not node.enabled:
        reason = f'нода «{name}» пропущена: выключена и не в подписке'
        _notify(session, name, reason)
        return UpdateResult(node.id or 0, name, ok=False, skipped=True, reason=reason)
    try:
        info = check_updates(node)
    except XuiError as exc:
        message = f'нода «{name}» не отвечает: {exc}'
        node.update_state = 'failed'
        session.add(node)
        session.commit()
        _notify(session, name, message)
        return UpdateResult(node.id or 0, name, ok=False, message=message)
    session.add(node)
    session.commit()

    want_panel = kind in ('panel', 'both') and info['panel_differs']
    want_xray = kind in ('xray', 'both') and info['xray_differs']
    if not want_panel and not want_xray:
        if kind == 'panel':
            message = 'панель актуальна'
        elif kind == 'xray':
            message = 'ядро актуально'
        else:
            message = 'актуально'
        return UpdateResult(node.id or 0, name, ok=True, message=message)

    result = UpdateResult(node.id or 0, name, ok=True)

    # Шаг панели: безопасно, без ограничения пулом.
    if want_panel:
        ok, msg = _update_panel_step(node)
        if not ok:
            message = f'нода «{name}»: панель не обновилась — {msg}'
            node.update_state = 'failed'
            session.add(node)
            session.commit()
            _notify(session, name, message)
            return UpdateResult(node.id or 0, name, ok=False, message=message)
        result.panel_updated = True
        node.xui_version = info['panel_latest']
        session.add(node)
        session.commit()

    # Шаг ядра: с ожиданием возврата и шагом отката при сбое.
    if want_xray:
        prev_xray = info['xray_current']
        ok, msg = _update_xray_step(node, info['xray_latest'])
        if not ok:
            # Шаг отката: возвращаем прежнюю версию ядра, чтобы нода осталась рабочей.
            rb_ok, rb_msg = _rollback_xray(node, prev_xray)
            node.update_state = 'failed'
            if rb_ok:
                node.xray_version = prev_xray
                session.add(node)
                session.commit()
                message = (
                    f'нода «{name}»: обновление ядра не удалось — {msg}; '
                    f'откатили на {prev_xray}'
                )
                _notify(session, name, message)
                return UpdateResult(
                    node.id or 0, name, ok=False, message=message,
                    panel_updated=result.panel_updated, rolled_back=True,
                )
            session.add(node)
            session.commit()
            message = (
                f'нода «{name}»: обновление ядра не удалось — {msg}; '
                f'откат тоже не прошёл: {rb_msg}'
            )
            _notify(session, name, message)
            return UpdateResult(
                node.id or 0, name, ok=False, message=message,
                panel_updated=result.panel_updated, rolled_back=False,
            )
        result.xray_updated = True
        node.xray_version = info['xray_latest']

    node.update_state = 'success'
    node.update_checked_at = utcnow()
    session.add(node)
    session.commit()
    # Уведомление об успехе — чтобы в жёлтом блоке было видно, что именно обновили.
    bits = []
    if result.panel_updated:
        bits.append(f'панель → {info["panel_latest"]}')
    if result.xray_updated:
        bits.append(f'ядро → {info["xray_latest"]}')
    if bits:
        _notify(session, name, f'нода «{name}» обновлена: ' + ', '.join(bits))
    return result


