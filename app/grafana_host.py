"""Поднять Grafana на отдельном сервере и закрыть её.

Повторный запуск приводит сервер к тому же виду и не удаляет тома:
история метрик и пароль, уже записанный в Grafana, сохраняются.
Пароль администратора скрипт выставляет заново из scripts/grafana.env,
так что файл остаётся источником правды.

Grafana только рисует. Ряды принимает VictoriaMetrics на той же машине.
Снаружи опубликованы порты Caddy 80 и 443. 3000 и 8428 в хост не
пробрасываются: Docker обходит ufw, поэтому закрытый порт файрвола
не защитил бы экспортёр, если его опубликовать.

Приём метрик — POST https://<хост>/api/v1/write с заголовком
Authorization: Bearer <токен>. Без токена Caddy отвечает 401.
Остальной API VictoriaMetrics снаружи не открыт.
Сертификат всегда Let's Encrypt. На голый IP центр отдаёт только
профиль shortlived, он живёт около шести дней, Caddy продлевает сам.
"""
from __future__ import annotations

import re
import secrets
import shlex
import string
from dataclasses import dataclass
from pathlib import Path

from app.fail2ban import clean_ip_token, jail_config
from app.xui_install import is_ipv4

GRAFANA_IMAGE = 'grafana/grafana:13.3.1'
VM_IMAGE = 'victoriametrics/victoria-metrics:v1.156.0'
CADDY_IMAGE = 'caddy:2'
ROOT_DIR = '/opt/grafana'
RETENTION = '30d'
ACME_EMAIL = 'admin@aegis-gate.ru'

_USER = re.compile(r'^[A-Za-z][A-Za-z0-9]{0,31}$')
_PASSWORD = re.compile(r'^[A-Za-z0-9-]{12,128}$')
_TOKEN = re.compile(r'^[0-9a-f]{32,128}$')
_DOMAIN = re.compile(
    r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
)
_EMAIL = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
_ENV_KEY = re.compile(r'^[A-Z][A-Z0-9_]{0,63}$')


@dataclass(frozen=True)
class GrafanaHost:
    host: str
    domain: str
    admin_user: str
    admin_password: str
    write_token: str
    ssh_port: int
    master_ip: str
    acme_email: str


def new_admin_password() -> str:
    pool = string.ascii_letters + string.digits
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        '-',
    ]
    chars.extend(secrets.choice(pool) for _ in range(24))
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


def new_write_token() -> str:
    return secrets.token_hex(24)


def load_env_file(path: Path) -> None:
    import os

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


def update_env_file(path: Path, updates: dict[str, str]) -> None:
    for key, value in updates.items():
        if not _ENV_KEY.fullmatch(key):
            raise ValueError(f'некорректный ключ {key}')
        if '\n' in value or '\r' in value:
            raise ValueError(f'{key} не должен содержать перевод строки')
    lines = path.read_text(encoding='utf-8').splitlines() if path.is_file() else []
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        stripped = raw.strip()
        body = stripped[7:].strip() if stripped.startswith('export ') else stripped
        if not stripped or stripped.startswith('#') or '=' not in body:
            out.append(raw)
            continue
        key = body.split('=', 1)[0].strip()
        if key in updates:
            out.append(f'{key}={updates[key]}')
            seen.add(key)
        else:
            out.append(raw)
    for key, value in updates.items():
        if key not in seen:
            out.append(f'{key}={value}')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(out) + '\n', encoding='utf-8')


def redact(text: str, secrets_to_hide: list[str]) -> str:
    out = text or ''
    for secret in sorted({item for item in secrets_to_hide if len(item) >= 4}, key=len, reverse=True):
        out = out.replace(secret, '***')
    return out


def parse_markers(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in (text or '').splitlines():
        if line.startswith('GRAFANA_') and '=' in line:
            key, value = line.split('=', 1)
            found[key] = value.strip()
    return found


def site_host(spec: GrafanaHost) -> str:
    _check(spec)
    return spec.domain or spec.host


def origin(spec: GrafanaHost) -> str:
    return 'https://' + site_host(spec)


def write_url(spec: GrafanaHost) -> str:
    return origin(spec) + '/api/v1/write'


def compose_text(spec: GrafanaHost) -> str:
    host = site_host(spec)
    environment = [
        'GF_USERS_ALLOW_SIGN_UP: "false"',
        'GF_USERS_ALLOW_ORG_CREATE: "false"',
        'GF_AUTH_ANONYMOUS_ENABLED: "false"',
        'GF_AUTH_BASIC_STRONG_PASSWORD_POLICY: "true"',
        'GF_SECURITY_DISABLE_BRUTE_FORCE_LOGIN_PROTECTION: "false"',
        'GF_SECURITY_COOKIE_SECURE: "true"',
        'GF_ANALYTICS_REPORTING_ENABLED: "false"',
        'GF_ANALYTICS_CHECK_FOR_UPDATES: "false"',
        f'GF_SERVER_ROOT_URL: "https://{host}/"',
        f'GF_SERVER_DOMAIN: "{host}"',
    ]
    if spec.domain:
        environment.append('GF_SECURITY_STRICT_TRANSPORT_SECURITY: "true"')
        environment.append('GF_SECURITY_STRICT_TRANSPORT_SECURITY_MAX_AGE_SECONDS: "31536000"')
    env_block = '\n'.join(f'      {line}' for line in environment)
    return f'''name: grafana

services:
  victoriametrics:
    image: {VM_IMAGE}
    command:
      - -storageDataPath=/vm-data
      - -retentionPeriod={RETENTION}
    volumes:
      - vm-data:/vm-data
    restart: unless-stopped

  grafana:
    image: {GRAFANA_IMAGE}
    env_file:
      - .env
    environment:
{env_block}
    volumes:
      - grafana-data:/var/lib/grafana
      - ./provisioning/datasources:/etc/grafana/provisioning/datasources:ro
    depends_on:
      - victoriametrics
    restart: unless-stopped

  caddy:
    image: {CADDY_IMAGE}
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    depends_on:
      - grafana
      - victoriametrics
    restart: unless-stopped

volumes:
  grafana-data:
  vm-data:
  caddy-data:
  caddy-config:
'''


def caddy_text(spec: GrafanaHost) -> str:
    site = site_host(spec)
    # Браузер, открывая https://IP, не присылает SNI. default_sni заставляет
    # Caddy отдать сертификат этого адреса, а не внутреннего адреса контейнера.
    # Отдельный редирект с 80-го порта не пишем: его перехват ломает проверку
    # Let's Encrypt, а редирект Caddy делает сам.
    head = [
        '{',
        f'    email {spec.acme_email}',
        f'    default_sni {site}',
        '}',
    ]
    site_lines = [f'{site} {{']
    if not spec.domain:
        site_lines.extend(
            [
                '    tls {',
                '        issuer acme {',
                '            profile shortlived',
                '        }',
                '    }',
            ]
        )
    site_lines.extend(
        [
            '    handle /api/v1/write {',
            '        route {',
            f'            @writer header Authorization "Bearer {spec.write_token}"',
            '            reverse_proxy @writer victoriametrics:8428',
            '            respond "unauthorized" 401',
            '        }',
            '    }',
            '    handle {',
            '        reverse_proxy grafana:3000',
            '    }',
            '}',
        ]
    )
    return '\n'.join(head) + '\n\n' + '\n'.join(site_lines) + '\n'


def datasource_text() -> str:
    return '''apiVersion: 1
datasources:
  - name: VictoriaMetrics
    uid: victoriametrics
    type: prometheus
    access: proxy
    url: http://victoriametrics:8428
    isDefault: true
    editable: false
    jsonData:
      timeInterval: 15s
'''


def dashboard_script(site: str) -> str:
    """Загрузить управляемый дашборд через локальный Caddy с проверкой TLS."""
    import ipaddress

    if not _DOMAIN.fullmatch(site):
        ipaddress.ip_address(site)
    return '\n'.join(_dashboard_import(site, Path(__file__).with_name(filename).read_text(encoding='utf8'))
                     for filename in ('node_dashboard.json', 'connectivity_dashboard.json'))


def _dashboard_import(site, payload):
    return f"""(
cd /opt/grafana
user=$(sed -n 's/^GF_SECURITY_ADMIN_USER=//p' .env)
pass=$(sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p' .env)
curl -fsS --max-time 30 --resolve '{site}:443:127.0.0.1' -u "$user:$pass" -H 'Content-Type: application/json' --data-binary @- 'https://{site}/api/dashboards/db' >/dev/null <<'DASHBOARD_JSON'
{payload.rstrip()}
DASHBOARD_JSON
)
"""


def env_text(spec: GrafanaHost) -> str:
    _check(spec)
    return (
        f'GF_SECURITY_ADMIN_USER={spec.admin_user}\n'
        f'GF_SECURITY_ADMIN_PASSWORD={spec.admin_password}\n'
    )


def remote_script(spec: GrafanaHost) -> str:
    _check(spec)
    puts = '\n'.join(
        [
            _put(f'{ROOT_DIR}/docker-compose.yml', compose_text(spec)),
            _put(f'{ROOT_DIR}/.env', env_text(spec)),
            _put(f'{ROOT_DIR}/Caddyfile', caddy_text(spec)),
            _put(f'{ROOT_DIR}/write.token', spec.write_token + '\n'),
            _put(
                f'{ROOT_DIR}/provisioning/datasources/victoriametrics.yml',
                datasource_text(),
            ),
        ]
    )
    script = r'''set -eu
export PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
export DEBIAN_FRONTEND=noninteractive
if [[ ! -r /etc/os-release ]] || ! grep -Eq 'debian|ubuntu' /etc/os-release; then
  echo "GRAFANA_ERROR=нужен Debian или Ubuntu"
  exit 2
fi
__DOCKER__
install -d -m 700 __ROOT__
install -d -m 755 __ROOT__/provisioning/datasources
umask 077
__FILES__
chmod 755 __ROOT__/provisioning __ROOT__/provisioning/datasources
chmod 644 __ROOT__/docker-compose.yml __ROOT__/provisioning/datasources/victoriametrics.yml
chmod 600 __ROOT__/.env __ROOT__/Caddyfile __ROOT__/write.token
chmod 700 __ROOT__
cd __ROOT__
echo "Записываю конфиг"
echo "Поднимаю контейнеры"
if ! docker compose up -d --remove-orphans >/tmp/grafana-compose.log 2>&1; then
  echo "GRAFANA_ERROR=контейнеры не поднялись"
  tail -n 40 /tmp/grafana-compose.log || true
  exit 1
fi
docker compose exec -T caddy rm -rf /data/caddy/certificates/local </dev/null >/dev/null 2>&1 || true
docker compose restart caddy </dev/null >/dev/null
docker compose restart grafana </dev/null >/dev/null
site=__SITE__
echo "Жду сертификат Let's Encrypt"
login_code=000
for _try in $(seq 1 40); do
  if [ $((_try % 4)) -eq 1 ]; then
    echo "Сертификат Let's Encrypt ещё не готов, попытка $_try"
  fi
  login_code=$(curl -fsS -o /dev/null -w '%{http_code}' --max-time 8 --resolve "$site:443:127.0.0.1" "https://$site/login" || true)
  if [ "$login_code" = "200" ]; then
    echo "Страница входа открылась"
    break
  fi
  sleep 3
done
if [ "$login_code" != "200" ]; then
  echo "GRAFANA_ERROR=сертификат Let's Encrypt не выпустился или Grafana не открылась, код $login_code"
  docker compose logs --tail=80 caddy || true
  exit 1
fi
pass=$(sed -n 's/^GF_SECURITY_ADMIN_PASSWORD=//p' __ROOT__/.env | head -n 1)
reset_ok=0
set -o pipefail
for _try in $(seq 1 15); do
  if printf '%s\n' "$pass" | docker compose exec -T grafana grafana cli admin reset-admin-password --password-from-stdin >/tmp/grafana-reset.log 2>&1; then
    reset_ok=1
    break
  fi
  sleep 2
done
set +o pipefail
if [ "$reset_ok" != "1" ]; then
  echo "GRAFANA_ERROR=не удалось записать пароль администратора"
  cat /tmp/grafana-reset.log || true
  rm -f /tmp/grafana-reset.log
  exit 1
fi
rm -f /tmp/grafana-reset.log
write_body=$(mktemp)
write_code=$(curl -sS -o "$write_body" -w '%{http_code}' --max-time 8 --resolve "$site:443:127.0.0.1" -X POST "https://$site/api/v1/write" || true)
if [ "$write_code" != "401" ] || ! grep -qx 'unauthorized' "$write_body"; then
  echo "GRAFANA_ERROR=приём метрик без токена не закрыт (код $write_code)"
  rm -f "$write_body"
  exit 1
fi
rm -f "$write_body"
token=$(cat __ROOT__/write.token)
auth_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 --resolve "$site:443:127.0.0.1" -X POST -H "Authorization: Bearer $token" "https://$site/api/v1/write" || true)
unset token pass
case "$auth_code" in
  204|400) ;;
  *)
    echo "GRAFANA_ERROR=запись метрик с токеном ответила $auth_code"
    exit 1
    ;;
esac
echo "Сверяю файрвол"
__UFW__
echo "Включаю fail2ban"
__GUARD__
echo GRAFANA_URL=__ORIGIN__
echo GRAFANA_USER=__USER__
echo GRAFANA_WRITE=__WRITE__
__DASHBOARD__
echo GRAFANA_READY=1
'''
    return (
        script.replace('__DOCKER__', _docker_install())
        .replace('__ROOT__', ROOT_DIR)
        .replace('__FILES__', puts)
        .replace('__DASHBOARD__', dashboard_script(site_host(spec)))
        .replace('__SITE__', shlex.quote(site_host(spec)))
        .replace('__UFW__', _ufw(spec.ssh_port).rstrip())
        .replace('__GUARD__', _guard(spec).rstrip())
        .replace('__ORIGIN__', origin(spec))
        .replace('__USER__', spec.admin_user)
        .replace('__WRITE__', write_url(spec))
    )


def _check(spec: GrafanaHost) -> None:
    if not is_ipv4(spec.host):
        raise ValueError('IP сервера Grafana должен быть IPv4')
    if spec.domain and not _DOMAIN.fullmatch(spec.domain):
        raise ValueError('домен Grafana указан неверно')
    if not _USER.fullmatch(spec.admin_user):
        raise ValueError('логин Grafana: латиница и цифры, до 32 символов')
    if not _password_ok(spec.admin_password):
        raise ValueError('пароль Grafana: 12–128 символов, большие и маленькие буквы, цифра и дефис')
    if not _TOKEN.fullmatch(spec.write_token):
        raise ValueError('токен записи: 32–128 шестнадцатеричных символов')
    if spec.ssh_port < 1 or spec.ssh_port > 65535:
        raise ValueError('SSH-порт вне диапазона')
    if spec.master_ip and not is_ipv4(spec.master_ip):
        raise ValueError('IP мастера должен быть IPv4')
    if not _EMAIL.fullmatch(spec.acme_email):
        raise ValueError('нужна почта для сертификата Let\'s Encrypt')


def _password_ok(value: str) -> bool:
    if not _PASSWORD.fullmatch(value or ''):
        return False
    return (
        any(char.isupper() for char in value)
        and any(char.islower() for char in value)
        and any(char.isdigit() for char in value)
        and '-' in value
    )


def _put(path: str, body: str) -> str:
    marker = 'GRAFANA_FILE'
    if marker in body:
        raise ValueError(f'файл {path} содержит маркер записи')
    if not body.endswith('\n'):
        body += '\n'
    return f"cat > {shlex.quote(path)} <<'{marker}'\n{body}{marker}\n"


def _docker_install() -> str:
    return '''if ! command -v curl >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "Ставлю Docker"
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable docker >/dev/null 2>&1 || true
  systemctl start docker >/dev/null 2>&1 || true
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq docker-compose-plugin
fi'''


def _ufw(ssh_port: int) -> str:
    from app.firewall import _script
    from app.models import Node

    node = Node(
        name='grafana',
        panel_url='https://203.0.113.10',
        public_host='203.0.113.10',
        ssh_port=int(ssh_port or 22),
    )
    return _script(node, {443})


def _ignore(master_ip: str) -> str:
    parts = ['127.0.0.1/8', '::1']
    master = clean_ip_token(master_ip)
    if master and master not in parts:
        parts.append(master)
    return ' '.join(parts)


def _guard(spec: GrafanaHost) -> str:
    jail = jail_config(spec.ssh_port, _ignore(spec.master_ip))
    if 'JAIL_EOF' in jail:
        raise ValueError('конфиг fail2ban содержит маркер записи')
    return f'''if ! command -v fail2ban-client >/dev/null 2>&1; then
  echo "Ставлю fail2ban"
  apt-get update -qq
  apt-get install -y -qq fail2ban
fi
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/master.local <<'JAIL_EOF'
{jail}JAIL_EOF
systemctl enable fail2ban >/dev/null
if ! systemctl restart fail2ban; then
  echo "GRAFANA_ERROR=fail2ban не запустился"
  exit 1
fi
'''


def apply_grafana_install(session, node_id: int, runner=None) -> None:
    """Поставить Grafana на карточку чистого VPS. В подписку сервер не включается."""
    from app.settings import settings
    from app.xui import normalize_panel_url
    from app.xui_install import _clip, _fail, _visible_output, _with_adopt, run_ssh

    from app.models import Node

    node = session.get(Node, node_id)
    if node is None or (node.install_state or '') != 'installing':
        return
    host = (node.public_host or '').strip()
    user = (node.ssh_user or 'root').strip() or 'root'
    adopt_logs: list[str] = []
    if runner is None:
        from app.ssh_access import AUTH_NONE, adopt_node, resolved_auth

        adopted = adopt_node(node, session)
        adopt_logs = list(adopted.logs)
        session.refresh(node)
        if resolved_auth(node) == AUTH_NONE:
            _fail(session, node, '\n'.join(adopt_logs) or 'SSH не открылся')
            return
    try:
        spec = GrafanaHost(
            host=host,
            domain='',
            admin_user='admin',
            admin_password=new_admin_password(),
            write_token=new_write_token(),
            ssh_port=int(node.ssh_port or 22),
            master_ip=(settings.master_ip or '').strip(),
            acme_email=ACME_EMAIL,
        )
        script = remote_script(spec)
    except ValueError as exc:
        _fail(session, node, _with_adopt(adopt_logs, str(exc)))
        return
    try:
        if runner is None:
            from app.ssh_access import AUTH_BOTH, AUTH_KEY, PRIVATE_PATH, resolved_auth

            use_key = resolved_auth(node) in {AUTH_KEY, AUTH_BOTH} and not (node.ssh_password or '').strip()
            node.install_log = _clip((node.install_log or '').rstrip() + '\nЗахожу по SSH')
            session.add(node)
            session.commit()

            def _progress(line: str) -> None:
                text = (line or '').strip()
                if not text or text.startswith('GRAFANA_') or text.startswith('MASTER_'):
                    return
                folded = text.casefold()
                if 'парол' in folded or 'токен' in folded:
                    return
                node.install_log = _clip((node.install_log or '').rstrip() + '\n' + text)
                session.add(node)
                session.commit()

            code, output = run_ssh(
                host,
                user,
                script,
                str(PRIVATE_PATH) if use_key else '',
                node.ssh_password,
                port=int(node.ssh_port or 22),
                prefer_key=use_key,
                on_line=_progress,
            )
        else:
            code, output = runner(
                host,
                user,
                script,
                '',
                node.ssh_password,
                port=int(node.ssh_port or 22),
            )
    except Exception as exc:
        _fail(session, node, _with_adopt(adopt_logs, f'Не удалось зайти по SSH: {exc}'))
        return
    markers = parse_markers(output)
    url = (markers.get('GRAFANA_URL') or '').strip()
    if code != 0 or markers.get('GRAFANA_ERROR') or markers.get('GRAFANA_READY') != '1' or not url:
        message = (markers.get('GRAFANA_ERROR') or '').strip()
        if not message:
            message = _visible_output(output) or f'установщик завершился с кодом {code}'
        _fail(session, node, _with_adopt(adopt_logs, redact(message, [spec.admin_password, spec.write_token])))
        return
    node.panel_url = normalize_panel_url(url)
    node.public_host = host
    from app.exporters import remember_grafana_target

    remember_grafana_target(session, node.panel_url.rstrip('/') + '/api/v1/write', spec.write_token)
    node.install_state = 'done'
    node.enabled = False
    node.last_error = ''
    node.firewall_on = True
    node.firewall_note = 'ufw и fail2ban'
    node.install_log = _clip(
        _with_adopt(
            adopt_logs,
            '\n'.join(
                [
                    _visible_output(output),
                    f'Grafana: {node.panel_url}',
                    'Логин: admin',
                    f'Пароль: {spec.admin_password}',
                    f"Приём метрик: {markers.get('GRAFANA_WRITE') or write_url(spec)}",
                    f'Токен записи: {spec.write_token}',
                    'В подписку сервер не входит.',
                ]
            ),
        )
    )
    session.add(node)
    session.commit()


def start_grafana_install(node_id: int) -> None:
    import threading

    from sqlmodel import Session

    from app.database import engine

    def _thread() -> None:
        with Session(engine) as session:
            try:
                apply_grafana_install(session, node_id)
            except Exception as exc:
                from app.models import Node
                from app.xui_install import _fail

                node = session.get(Node, node_id)
                if node is not None and (node.install_state or '') == 'installing':
                    _fail(session, node, f'Установка прервалась: {exc}')

    threading.Thread(target=_thread, name=f'grafana-install-{node_id}', daemon=True).start()
