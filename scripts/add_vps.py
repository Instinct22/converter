#!/usr/bin/env python3
"""Поставить 3x-ui на новый VPS и завести его в Master.

Официальный установщик
закреплён по версии и SHA-256 в app/xui_install.py. У него есть тихий режим: без TTY и с
XUI_NONINTERACTIVE=1 он не задаёт вопросы, а берёт XUI_USERNAME,
XUI_PASSWORD, XUI_PANEL_PORT, XUI_WEB_BASE_PATH, XUI_DB_TYPE, XUI_SSL_MODE.

Пример:
  py -3 scripts/add_vps.py

Логин, пароли и адрес VPS берутся из scripts/add_vps.env
(файл в git не попадает). Аргументы командной строки, если указаны, важнее файла.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.ssh_access import HostIdentityError, PRIVATE_PATH, ensure_fleet_key  # noqa: E402
from app.xui_install import (  # noqa: E402
    choose_panel_port as panel_port,
    parse_master_lines,
    rand,
    remote_script,
    run_ssh,
)

ENV_FILE = Path(__file__).with_name('add_vps.env')


def load_env(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].strip()
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


class Master:
    def __init__(self, base: str, username: str, password: str) -> None:
        self.base = base.rstrip('/')
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        body = urllib.parse.urlencode({'username': username, 'password': password}).encode()
        req = urllib.request.Request(self.base + '/login', data=body, method='POST')
        try:
            self.opener.open(req, timeout=30)
        except urllib.error.HTTPError as exc:
            if exc.code not in {302, 303}:
                raise SystemExit(f'Master login HTTP {exc.code}') from exc
        if not any(cookie.name == 'master_session' for cookie in self.jar):
            raise SystemExit('Master не пустил: проверьте логин и пароль')

    def call(self, method: str, path: str, payload: dict | None = None) -> object:
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=180) as resp:
                raw = resp.read().decode()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode('utf-8', 'replace')
            raise SystemExit(f'{method} {path} HTTP {exc.code}: {detail[:500]}') from exc
        if not raw:
            return {}
        return json.loads(raw)


def main() -> None:
    load_env(ENV_FILE)
    parser = argparse.ArgumentParser(description='Установить 3x-ui и добавить сервер в Master')
    parser.add_argument('--host', default=os.environ.get('VPS_HOST', ''), help='IP нового VPS')
    parser.add_argument('--ssh-user', default=os.environ.get('VPS_SSH_USER', 'root'))
    parser.add_argument('--ssh-key', default=os.environ.get('VPS_SSH_KEY', ''))
    parser.add_argument('--ssh-password', default=os.environ.get('VPS_SSH_PASSWORD', ''))
    parser.add_argument('--name', default=os.environ.get('VPS_NAME', ''), help='Имя в Master, например Netherlands-01')
    parser.add_argument('--flag', default=os.environ.get('VPS_FLAG', ''), help='Флаг, например NL')
    parser.add_argument('--master', default=os.environ.get('MASTER_URL', 'https://master.aegis-gate.ru'))
    parser.add_argument('--master-user', default=os.environ.get('MASTER_USER', ''))
    parser.add_argument('--master-password', default=os.environ.get('MASTER_PASSWORD', ''))
    parser.add_argument(
        '--ssl',
        choices=('none', 'ip'),
        default='ip',
        help='ip: сертификат Let\'s Encrypt на IP, порт 80 открыт. none: панель по HTTP',
    )
    args = parser.parse_args()
    missing = [
        name
        for name, value in (
            ('VPS_HOST', args.host),
            ('VPS_NAME', args.name),
            ('VPS_FLAG', args.flag),
            ('MASTER_USER', args.master_user),
            ('MASTER_PASSWORD', args.master_password),
        )
        if not value
    ]
    if missing:
        raise SystemExit(f'Заполните {", ".join(missing)} в {ENV_FILE}')
    if not args.ssh_key:
        ensure_fleet_key()
        args.ssh_key = str(PRIVATE_PATH)
    if not args.ssh_password and not args.ssh_key:
        raise SystemExit(f'Заполните VPS_SSH_PASSWORD или VPS_SSH_KEY в {ENV_FILE}')
    if not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', args.host):
        raise SystemExit('VPS_HOST должен быть IPv4')

    from app.xui import XuiError, require_panel_transport
    try:
        require_panel_transport(args.master)
        if args.ssl == 'none':
            require_panel_transport(f'http://{args.host}')
    except XuiError as exc:
        raise SystemExit(str(exc)) from exc

    username = rand(12)
    password = rand(20)
    web_base = rand(18)
    port = panel_port()
    master = Master(args.master, args.master_user, args.master_password)
    templates = master.call('GET', '/api/templates')
    if not isinstance(templates, list):
        raise SystemExit('Master не отдал список шаблонов')
    enabled = [row for row in templates if row.get('enabled')]
    template_ids = [int(row['id']) for row in enabled if row.get('id') is not None]
    script = remote_script(
        username=username,
        password=password,
        web_base=web_base,
        port=port,
        server_ip=args.host,
        ssl_mode=args.ssl,
    )
    print(f'Ставлю 3x-ui на {args.host}. Это несколько минут.', flush=True)
    try:
        try:
            code, output = run_ssh(
                args.host, args.ssh_user, script, args.ssh_key, '', prefer_key=True,
            )
        except HostIdentityError:
            raise
        except RuntimeError:
            if not args.ssh_password:
                raise
            code, output = run_ssh(args.host, args.ssh_user, script, '', args.ssh_password)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    if code != 0:
        raise SystemExit(code)
    creds = parse_master_lines(output)
    if creds.get('MASTER_ERROR'):
        raise SystemExit(creds['MASTER_ERROR'])
    url = creds.get('MASTER_URL') or ''
    token = creds.get('MASTER_TOKEN') or ''
    if not url or not token:
        raise SystemExit('Установщик не вернул URL или API Token')

    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', prefix='xui-access-', suffix='.json',
                                     delete=False) as handoff:
        json.dump({'url': url, 'username': creds.get('MASTER_USER') or username,
                   'password': creds.get('MASTER_PASS') or password, 'api_token': token}, handoff)
    print('Реквизиты сохранены в личном временном файле:', handoff.name, flush=True)
    created = master.call(
        'POST',
        '/api/nodes',
        {
            'flag': args.flag,
            'name': args.name,
            'clash_name': args.name,
            'panel_url': url,
            'api_token': token,
        },
    )
    node = created.get('node') if isinstance(created, dict) else None
    node_id = node.get('id') if isinstance(node, dict) else None
    if not node_id:
        raise SystemExit(f'Master не создал сервер: {created}')
    print('Сервер в Master:', node_id, flush=True)
    adopt_body = {'ssh_user': args.ssh_user, 'ssh_port': 22}
    if args.ssh_password:
        adopt_body['ssh_password'] = args.ssh_password
    adopted = master.call('POST', f'/api/nodes/{node_id}/adopt-key', adopt_body)
    adopt_logs = adopted.get('logs') if isinstance(adopted, dict) else []
    print('Ключ:', ' · '.join(adopt_logs or []), flush=True)
    refreshed = master.call(
        'POST',
        f'/api/nodes/{node_id}/refresh-templates',
        {'template_ids': template_ids},
    )
    logs = refreshed.get('logs') if isinstance(refreshed, dict) else []
    print('Входы:', ' · '.join(logs or []), flush=True)
    clients = master.call('GET', '/api/clients')
    if isinstance(clients, list):
        for client in clients:
            cid = client.get('id')
            if cid is None:
                continue
            result = master.call('POST', f'/api/clients/{cid}/provision')
            client_logs = result.get('logs') if isinstance(result, dict) else []
            own = [line for line in client_logs or [] if args.name in line or args.host in line]
            print(client.get('name'), ':', ' · '.join(own or client_logs or ['ok']), flush=True)

    print()
    print('Панель 3x-ui')
    print('  URL:      ', url)
    print('Панель открыта из интернета по этому URL.')
    print('Файрвол и fail2ban этот скрипт не трогает: их ставит Master.')


if __name__ == '__main__':
    main()
