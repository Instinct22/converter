#!/usr/bin/env python3
"""Поставить 3x-ui на новый VPS и завести его в Master.

Официальный установщик
https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh
в репозитории Master не лежит. У него есть тихий режим: без TTY и с
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
import secrets
import shlex
import string
import subprocess
import sys
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

INSTALL_URL = 'https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh'
ENV_FILE = Path(__file__).with_name('add_vps.env')
# Порты Reality, которые клиенты открывают снаружи, если шаблоны ещё не прочитаны.
DEFAULT_PUBLIC_PORTS = (443, 8443)


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


def rand(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def panel_port() -> int:
    banned = {22, 80, 443, 8443, 2096}
    while True:
        port = secrets.randbelow(50000) + 10000
        if port not in banned:
            return port


def remote_script(
    *,
    username: str,
    password: str,
    web_base: str,
    port: int,
    public_ports: list[int],
    master_ip: str,
    server_ip: str,
    ssl_mode: str,
) -> str:
    exports = '\n'.join(
        [
            f'export XUI_NONINTERACTIVE=1',
            f'export XUI_USERNAME={shlex.quote(username)}',
            f'export XUI_PASSWORD={shlex.quote(password)}',
            f'export XUI_WEB_BASE_PATH={shlex.quote(web_base)}',
            f'export XUI_PANEL_PORT={port}',
            f'export XUI_DB_TYPE=sqlite',
            f'export XUI_SSL_MODE={shlex.quote(ssl_mode)}',
            f'export XUI_SERVER_IP={shlex.quote(server_ip)}',
        ]
    )
    ports = ' '.join(str(item) for item in public_ports)
    return f'''set -u
{exports}
if command -v x-ui >/dev/null 2>&1 || [[ -x /usr/local/x-ui/x-ui ]]; then
  echo "MASTER_ERROR=на сервере уже стоит x-ui, повторная установка сменит пароль. Остановился."
  exit 2
fi
if [[ ! -r /etc/os-release ]] || ! grep -Eq 'debian|ubuntu' /etc/os-release; then
  echo "MASTER_ERROR=нужен Debian или Ubuntu"
  exit 2
fi
export DEBIAN_FRONTEND=noninteractive
if ! apt-get update -qq || ! apt-get install -y -qq curl ca-certificates; then
  echo "MASTER_ERROR=не удалось поставить curl"
  exit 1
fi
installer=$(mktemp)
if ! curl -fsSL {shlex.quote(INSTALL_URL)} -o "$installer"; then
  echo "MASTER_ERROR=не скачался установщик 3x-ui"
  exit 1
fi
if ! bash "$installer"; then
  echo "MASTER_ERROR=установщик 3x-ui завершился с ошибкой"
  exit 1
fi
rm -f "$installer"
if [[ ! -x /usr/local/x-ui/x-ui ]]; then
  echo "MASTER_ERROR=x-ui не появился после установки"
  exit 1
fi
install -d -m 700 /etc/x-ui
if [[ -r /etc/x-ui/install-result.env ]]; then
  # shellcheck disable=SC1091
  source /etc/x-ui/install-result.env
fi
token="${{XUI_API_TOKEN:-}}"
if [[ -z "$token" && -x /usr/local/x-ui/x-ui ]]; then
  token=$(/usr/local/x-ui/x-ui setting -getApiToken | awk '/apiToken:/ {{print $2; exit}}')
fi
access="${{XUI_ACCESS_URL:-}}"
scheme="${{access%%://*}}"
host="${{XUI_SERVER_IP:-}}"
if [[ -z "$host" ]]; then
  host=$(curl -4 -fsS --max-time 5 https://api4.ipify.org || true)
fi
panel_port="${{XUI_PANEL_PORT}}"
base_path="${{XUI_WEB_BASE_PATH}}"
base_path="${{base_path#/}}"
probe() {{
  curl -ksS -o /dev/null -w "%{{http_code}}" --max-time 8 "$1" || true
}}
https_code=$(probe "https://127.0.0.1:${{panel_port}}/${{base_path}}/")
http_code=$(probe "http://127.0.0.1:${{panel_port}}/${{base_path}}/")
if [[ "$https_code" != "000" && -n "$https_code" ]]; then
  scheme=https
elif [[ "$http_code" != "000" && -n "$http_code" ]]; then
  scheme=http
fi
access="${{scheme}}://${{host}}:${{panel_port}}/${{base_path}}"
apt-get update -qq
apt-get install -y -qq ufw fail2ban >/dev/null
ssh_port=22
if [[ -n "${{SSH_CONNECTION:-}}" ]]; then
  ssh_port="${{SSH_CONNECTION##* }}"
fi
operator_ip=""
if [[ -n "${{SSH_CONNECTION:-}}" ]]; then
  operator_ip="${{SSH_CONNECTION%% *}}"
fi
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw limit "${{ssh_port}}/tcp"
for public_port in {ports}; do
  ufw allow "${{public_port}}/tcp"
done
if [[ "{ssl_mode}" == "ip" ]]; then
  ufw allow 80/tcp
fi
ufw allow "${{panel_port}}/tcp"
ufw --force enable
cat >/etc/fail2ban/jail.d/sshd-master.local <<EOF
[sshd]
enabled = true
port = $ssh_port
maxretry = 4
findtime = 10m
bantime = 1h
ignoreip = 127.0.0.1/8 ::1 {master_ip} $operator_ip
EOF
systemctl enable --now fail2ban >/dev/null 2>&1 || true
systemctl restart fail2ban >/dev/null 2>&1 || true
if [[ -z "$token" || -z "$host" || "$access" == *"://:"* ]]; then
  echo "MASTER_ERROR=установщик не вернул адрес или API Token"
  exit 1
fi
echo "MASTER_URL=$access"
echo "MASTER_USER=${{XUI_USERNAME}}"
echo "MASTER_PASS=${{XUI_PASSWORD}}"
echo "MASTER_TOKEN=$token"
echo "MASTER_PORT=$panel_port"
echo "MASTER_SSH_PORT=$ssh_port"
echo "MASTER_OPERATOR=$operator_ip"
'''


def run_ssh(host: str, user: str, script: str, key: str, password: str) -> tuple[int, str]:
    target = f'{user}@{host}'
    if password:
        try:
            import paramiko
        except ImportError as exc:
            raise SystemExit(
                'Для входа по паролю нужен paramiko: python3 -m pip install paramiko. '
                'Либо зайдите ключом: VPS_SSH_KEY в scripts/add_vps.env'
            ) from exc
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            username=user,
            password=password,
            timeout=25,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command('bash -s', timeout=900)
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        code = stdout.channel.recv_exit_status()
        client.close()
        return code, out + err
    cmd = [
        'ssh',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=25',
    ]
    if key:
        cmd.extend(['-i', key])
    cmd.extend([target, 'bash -s'])
    proc = subprocess.run(
        cmd,
        input=script.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.returncode, proc.stdout.decode('utf-8', 'replace')


def parse_master_lines(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith('MASTER_') and '=' in line:
            key, value = line.split('=', 1)
            found[key] = value.strip()
    return found


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


def host_of(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname or ''


def main() -> None:
    load_env(ENV_FILE)
    parser = argparse.ArgumentParser(description='Установить 3x-ui и добавить сервер в Master')
    parser.add_argument('--host', default=os.environ.get('VPS_HOST', ''), help='IP нового VPS')
    parser.add_argument('--ssh-user', default=os.environ.get('VPS_SSH_USER', 'root'))
    parser.add_argument('--ssh-key', default=os.environ.get('VPS_SSH_KEY', ''))
    parser.add_argument('--ssh-password', default=os.environ.get('VPS_SSH_PASSWORD', ''))
    parser.add_argument('--name', default=os.environ.get('VPS_NAME', ''), help='Имя в Master, например Netherlands-01')
    parser.add_argument('--flag', default=os.environ.get('VPS_FLAG', ''), help='Флаг, например NL')
    parser.add_argument('--master', default=os.environ.get('MASTER_URL', 'http://5.180.174.204:8080'))
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
    if not args.ssh_password and not args.ssh_key:
        raise SystemExit(f'Заполните VPS_SSH_PASSWORD или VPS_SSH_KEY в {ENV_FILE}')
    if not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', args.host):
        raise SystemExit('VPS_HOST должен быть IPv4')

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
    public_ports = sorted({int(row.get('port') or 0) for row in enabled} | set(DEFAULT_PUBLIC_PORTS))
    public_ports = [item for item in public_ports if item > 0]
    master_ip = host_of(args.master)
    script = remote_script(
        username=username,
        password=password,
        web_base=web_base,
        port=port,
        public_ports=public_ports,
        master_ip=master_ip,
        server_ip=args.host,
        ssl_mode=args.ssl,
    )
    print(f'Ставлю 3x-ui на {args.host}. Это несколько минут.', flush=True)
    code, output = run_ssh(args.host, args.ssh_user, script, args.ssh_key, args.ssh_password)
    sys.stdout.write(output)
    if code != 0:
        raise SystemExit(code)
    creds = parse_master_lines(output)
    if creds.get('MASTER_ERROR'):
        raise SystemExit(creds['MASTER_ERROR'])
    url = creds.get('MASTER_URL') or ''
    token = creds.get('MASTER_TOKEN') or ''
    if not url or not token:
        raise SystemExit('Установщик не вернул URL или API Token')

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
    print('  Логин:    ', creds.get('MASTER_USER') or username)
    print('  Пароль:   ', creds.get('MASTER_PASS') or password)
    print('  API Token:', token)
    print('Панель открыта из интернета по этому URL.')
    opened = ['SSH', 'панель ' + str(port)]
    if args.ssl == 'ip':
        opened.append('80 для продления сертификата')
    opened.append('порты Reality ' + ', '.join(str(item) for item in public_ports))
    print('Снаружи открыты:', ', '.join(opened) + '.')
    print('SSH режет fail2ban: 4 ошибки за 10 минут, бан на час.')


if __name__ == '__main__':
    main()
