"""Локальные фейковые панели 3x-ui для проверки блока обновлений.

Поднимает несколько HTTP-панелей на 127.0.0.1 разных портов и заводит соответствующие
ноды в БД мастера (rf_ok=True, чтобы пул пропускал обновление ядер). Реализует ровно те
эндпоинты, что зовёт XuiClient: status, inbounds/list, clients/onlines,
getPanelUpdateInfo, updatePanel, getUpdateStatus, getXrayVersion, installXray/<ver>.
После updatePanel/installXray версии в моке реально меняются — UI это подхватит.

Запуск из корня репозитория (виртуальное окружение):
    python scripts/mock_panels.py            # завести ноды + поднять моки (Ctrl+C — стоп)
    python scripts/mock_panels.py --seed     # только завести/перезаписать ноды
    python scripts/mock_panels.py --serve    # только поднять моки (ноды уже заведены)
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Имя ноды -> (порт, версия панели сейчас, версия панели доступна,
#              версия ядра сейчас, версия ядра доступна, включена ли нода)
MOCK_NODES = [
    {'name': 'MOCK-DE-1', 'flag': 'de', 'port': 20801,
     'panel_current': '3.0.5', 'panel_latest': '3.11',
     'xray_current': '25.9.8', 'xray_latest': '25.11.7', 'enabled': True},
    {'name': 'MOCK-NL-2', 'flag': 'nl', 'port': 20802,
     'panel_current': '3.11', 'panel_latest': '3.11',
     'xray_current': '25.11.7', 'xray_latest': '25.11.7', 'enabled': True},
    {'name': 'MOCK-US-3', 'flag': 'us', 'port': 20803,
     'panel_current': '2.6.2', 'panel_latest': '3.11',
     'xray_current': '25.9.8', 'xray_latest': '25.11.7', 'enabled': True},
    {'name': 'MOCK-FI-4', 'flag': 'fi', 'port': 20804,
     'panel_current': '3.0.5', 'panel_latest': '3.11',
     'xray_current': '25.9.8', 'xray_latest': '25.11.7', 'enabled': False},
]


class MockPanel:
    """Состояние одной фейковой панели: версии и статус последнего self-update."""

    def __init__(self, cfg: dict) -> None:
        self.name = cfg['name']
        self.port = cfg['port']
        self.panel_current = cfg['panel_current']
        self.panel_latest = cfg['panel_latest']
        self.xray_current = cfg['xray_current']
        self.xray_latest = cfg['xray_latest']
        self.update_state = 'idle'
        self.run_id = ''

    # --- ответы на эндпоинты ---
    def status(self) -> dict:
        return {
            'cpu': '4.0',
            'mem': {'current': 1_200_000_000, 'total': 4_000_000_000},
            'uptime': 360000,
            'xray': {'version': self.xray_current, 'state': 'running', 'running': True},
            'panelVersion': self.panel_current,
            'tcpCount': 0,
            'udpCount': 0,
        }

    def update_info(self) -> dict:
        return {'channel': 'main', 'currentVersion': self.panel_current, 'latestVersion': self.panel_latest}

    def xray_versions(self) -> list[str]:
        seen: list[str] = []
        for v in (self.xray_latest, self.xray_current, '25.10.5', '25.9.8'):
            if v and v not in seen:
                seen.append(v)
        return seen

    def do_update_panel(self) -> str:
        self.run_id = f'run-{self.port}-{abs(hash(self.panel_latest)) % 1000}'
        self.panel_current = self.panel_latest
        self.update_state = 'success'
        return self.run_id

    def do_install_xray(self, version: str) -> None:
        if version:
            self.xray_current = version


class Handler(BaseHTTPRequestHandler):
    """Раздаёт JSON по путям /panel/api/...; панель берётся из self.server.panel."""

    def log_message(self, *_args: object) -> None:  # тишина в консоли
        return

    def _drain_body(self) -> None:
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)

    def _send(self, payload: dict) -> None:
        raw = json.dumps(payload).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _handle(self) -> None:
        self._drain_body()
        panel: MockPanel = self.server.panel
        path = self.path.split('?', 1)[0]
        if path == '/panel/api/server/status':
            self._send({'success': True, 'obj': panel.status()})
        elif path in ('/panel/api/inbounds/list', '/panel/api/clients/list'):
            self._send({'success': True, 'obj': []})
        elif path in ('/panel/api/clients/onlines', '/panel/api/inbounds/onlines'):
            self._send({'success': True, 'obj': []})
        elif path == '/panel/api/server/getPanelUpdateInfo':
            self._send({'success': True, 'obj': panel.update_info()})
        elif path == '/panel/api/server/updatePanel':
            self._send({'success': True, 'obj': panel.do_update_panel()})
        elif path == '/panel/api/server/getUpdateStatus':
            self._send({'success': True, 'obj': {'runId': panel.run_id, 'state': panel.update_state}})
        elif path == '/panel/api/server/getXrayVersion':
            self._send({'success': True, 'obj': panel.xray_versions()})
        elif path.startswith('/panel/api/server/installXray/'):
            version = path.rsplit('/', 1)[-1]
            panel.do_install_xray(version)
            self._send({'success': True, 'obj': True})
        else:
            self._send({'success': False, 'msg': f'no route {path}', 'raw': True, 'status': 404})

    do_GET = _handle
    do_POST = _handle


def serve(panels: list[MockPanel]) -> list[ThreadingHTTPServer]:
    servers: list[ThreadingHTTPServer] = []
    for panel in panels:
        httpd = ThreadingHTTPServer(('127.0.0.1', panel.port), Handler)
        httpd.panel = panel  # type: ignore[attr-defined]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
    return servers


def seed_nodes(panels: list[MockPanel]) -> None:
    """Перезаписать тестовые ноды в БД мастера (по префиксу MOCK-)."""
    from sqlmodel import Session, select

    from app.database import engine, init_db
    from app.models import (
        ClientPlacement,
        Node,
        NodeInbound,
        NodeTemplateAssignment,
        utcnow,
    )

    init_db()
    with Session(engine) as session:
        stale = session.exec(select(Node).where(Node.name.like('MOCK-%'))).all()
        stale_ids = [node.id for node in stale if node.id is not None]
        # Сначала дочерние строки — иначе SQLite роняет DELETE по FOREIGN KEY.
        if stale_ids:
            for placement in session.exec(
                select(ClientPlacement).where(ClientPlacement.node_id.in_(stale_ids))
            ).all():
                session.delete(placement)
            for inbound in session.exec(
                select(NodeInbound).where(NodeInbound.node_id.in_(stale_ids))
            ).all():
                session.delete(inbound)
            for assignment in session.exec(
                select(NodeTemplateAssignment).where(NodeTemplateAssignment.node_id.in_(stale_ids))
            ).all():
                session.delete(assignment)
            session.commit()
        for node in stale:
            session.delete(node)
        session.commit()
        for order, panel in enumerate(panels):
            cfg = next(c for c in MOCK_NODES if c['name'] == panel.name)
            session.add(
                Node(
                    flag=cfg['flag'],
                    name=cfg['name'],
                    clash_name=cfg['name'],
                    panel_url=f'http://127.0.0.1:{panel.port}',
                    api_token=f'mock-token-{panel.port}',
                    public_host='127.0.0.1',
                    sub_scheme='http',
                    enabled=cfg['enabled'],
                    sort_order=order,
                    rf_ok=True,
                    rf_note='тестовый мок',
                    rf_checked_at=utcnow(),
                    xui_version=panel.panel_current,
                    xray_version=panel.xray_current,
                    panel_latest_version=panel.panel_latest,
                    xray_latest_version=panel.xray_latest,
                    version_checked_at=utcnow(),
                )
            )
        session.commit()


def print_table(panels: list[MockPanel]) -> None:
    print('\nТестовые панели 3x-ui:')
    print(f"{'НОДА':<12}{'URL':<24}{'3x-ui':<16}{'Xray':<16}{'вкл'}")
    for panel in panels:
        cfg = next(c for c in MOCK_NODES if c['name'] == panel.name)
        panel_col = f"{panel.panel_current}->{panel.panel_latest}" if panel.panel_current != panel.panel_latest else panel.panel_current
        xray_col = f"{panel.xray_current}->{panel.xray_latest}" if panel.xray_current != panel.xray_latest else panel.xray_current
        print(f"{panel.name:<12}{f'http://127.0.0.1:{panel.port}':<24}{panel_col:<16}{xray_col:<16}{'да' if cfg['enabled'] else 'нет'}")
    print('\nОткройте дашборд мастера → кнопка «Обновления» → «Проверить версии» → «Обновить выбранные».')
    print('Ctrl+C — остановить моки.\n')


def main() -> None:
    args = set(sys.argv[1:])
    panels = [MockPanel(cfg) for cfg in MOCK_NODES]
    if '--serve' not in args:
        seed_nodes(panels)
        print('Ноды MOCK-* заведены в БД мастера.')
    servers = serve(panels)
    print_table(panels)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        for httpd in servers:
            httpd.shutdown()
        print('\nМоки остановлены.')


if __name__ == '__main__':
    main()

