"""Поставить 3x-ui на чистый VPS из окна «Новый сервер».

Тот же установщик, что у scripts/add_vps.py. Карточка сервера создаётся
сразу, установка идёт в фоне и пишет журнал на карточку. Повторный запуск
на машину, где x-ui уже стоит, установщик не делает: смена пароля панели
из этого окна не предлагается.
"""
from __future__ import annotations

import secrets
import shlex
import string
import threading

from sqlmodel import Session, select

from app.activity import worker_state
from app.models import Node
from app.xui import normalize_panel_url, public_host_from_url

INSTALL_URL = 'https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh'
DEFAULT_PUBLIC_PORTS = (443, 8443)
_LOG_LIMIT = 12000


def rand(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def choose_panel_port() -> int:
    banned = {22, 80, 443, 8443, 2096}
    while True:
        port = secrets.randbelow(50000) + 10000
        if port not in banned:
            return port


def is_ipv4(value: str) -> bool:
    parts = (value or '').split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if len(part) > 1 and part.startswith('0'):
            return False
        if int(part) > 255:
            return False
    return True


def remote_script(
    *,
    username: str,
    password: str,
    web_base: str,
    port: int,
    server_ip: str,
    ssl_mode: str,
) -> str:
    exports = '\n'.join(
        [
            'export XUI_NONINTERACTIVE=1',
            f'export XUI_USERNAME={shlex.quote(username)}',
            f'export XUI_PASSWORD={shlex.quote(password)}',
            f'export XUI_WEB_BASE_PATH={shlex.quote(web_base)}',
            f'export XUI_PANEL_PORT={port}',
            'export XUI_DB_TYPE=sqlite',
            f'export XUI_SSL_MODE={shlex.quote(ssl_mode)}',
            f'export XUI_SERVER_IP={shlex.quote(server_ip)}',
        ]
    )
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
if [[ -z "$token" || -z "$host" || "$access" == *"://:"* ]]; then
  echo "MASTER_ERROR=установщик не вернул адрес или API Token"
  exit 1
fi
echo "MASTER_URL=$access"
echo "MASTER_USER=${{XUI_USERNAME}}"
echo "MASTER_PASS=${{XUI_PASSWORD}}"
echo "MASTER_TOKEN=$token"
echo "MASTER_PORT=$panel_port"
'''


def run_ssh(
    host: str,
    user: str,
    script: str,
    key: str,
    password: str,
    *,
    port: int = 22,
    prefer_key: bool = False,
    on_line=None,
) -> tuple[int, str]:
    from app.ssh_access import run_remote

    use_key = bool(key) and (prefer_key or not password)
    try:
        if use_key:
            code, out, err = run_remote(host, user, port, script, key_path=key, timeout=900, on_line=on_line)
        elif password:
            code, out, err = run_remote(host, user, port, script, password=password, timeout=900, on_line=on_line)
        else:
            raise RuntimeError('Нет SSH-ключа и пароля')
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(f'Не удалось зайти по SSH: {exc}') from exc
    return code, out + err


def parse_master_lines(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith('MASTER_') and '=' in line:
            key, value = line.split('=', 1)
            found[key] = value.strip()
    return found


def install_product(kind: str) -> str:
    value = (kind or 'xui').strip().lower()
    if value not in {'xui', 'grafana'}:
        raise ValueError('На чистый VPS можно поставить 3x-ui или Grafana')
    return value


def prepare_install(
    session: Session,
    *,
    flag: str,
    name: str,
    clash_name: str,
    host: str,
    ssh_user: str,
    ssh_password: str,
    ssh_port: int,
    kind: str = 'xui',
) -> Node:
    from app.flags import to_iso

    title = (name or '').strip()
    if not title:
        raise ValueError('Нужно название сервера')
    address = (host or '').strip()
    if not is_ipv4(address):
        raise ValueError('IP сервера должен быть IPv4')
    password = (ssh_password or '').strip()
    user = (ssh_user or 'root').strip() or 'root'
    port = int(ssh_port or 22)
    if port < 1 or port > 65535:
        raise ValueError('SSH-порт вне диапазона')
    taken = session.exec(select(Node).where(Node.public_host == address)).first()
    if taken is not None:
        raise ValueError(f'Сервер {taken.name} уже использует этот IP')
    product = install_product(kind)
    if product == 'grafana':
        opening = 'Ставлю Grafana. Это несколько минут. Адрес и пароль появятся здесь, когда установщик закончит.'
    else:
        opening = 'Ставлю 3x-ui. Это несколько минут. Логин панели появится здесь, когда установщик закончит.'
    node = Node(
        flag=to_iso(flag) or (flag or '').strip(),
        name=title,
        clash_name=(clash_name or title).strip(),
        panel_url='',
        api_token='',
        public_host=address,
        enabled=False,
        ssh_user=user,
        ssh_port=port,
        ssh_password=password,
        ssh_auth='password' if password else 'key',
        install_state='installing',
        install_ssl='ip',
        install_kind=product,
        install_log=opening,
    )
    session.add(node)
    session.flush()
    worker_state(session, node, 'install', 'Установка ' + product, 'running', 'Сервер добавлен в очередь')
    session.commit()
    session.refresh(node)
    return node


def _clip(text: str) -> str:
    return (text or '')[:_LOG_LIMIT]


def _with_adopt(logs: list[str], message: str) -> str:
    head = '\n'.join(line for line in logs if line).strip()
    body = (message or '').strip()
    if head and body:
        return _clip(head + '\n' + body)
    return _clip(head or body)


def _visible_output(output: str) -> str:
    lines: list[str] = []
    for line in (output or '').splitlines():
        if line.startswith('MASTER_'):
            continue
        text = line.strip()
        if text:
            lines.append(text)
    return '\n'.join(lines[-40:])


def _fail(session: Session, node: Node, message: str) -> None:
    worker_state(session, node, 'install', 'Установка сервера', 'error', message)
    node.install_state = 'failed'
    node.last_error = message[:240]
    node.install_log = _clip(message)
    session.add(node)
    session.commit()


def _success_log(output: str, creds: dict[str, str]) -> str:
    parts = [item for item in (_visible_output(output),) if item]
    parts.append(
        '\n'.join(
            [
                f"Панель: {creds.get('MASTER_URL') or ''}",
                f"Логин: {creds.get('MASTER_USER') or ''}",
                f"Пароль: {creds.get('MASTER_PASS') or ''}",
                'API Token сохранён в Master.',
            ]
        )
    )
    return _clip('\n'.join(parts))


def apply_install_result(session: Session, node_id: int, runner=None) -> None:
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
    script = remote_script(
        username=rand(12),
        password=rand(20),
        web_base=rand(18),
        port=choose_panel_port(),
        server_ip=host,
        ssl_mode=node.install_ssl or 'ip',
    )
    try:
        if runner is None:
            from app.ssh_access import AUTH_BOTH, AUTH_KEY, PRIVATE_PATH, resolved_auth

            use_key = resolved_auth(node) in {AUTH_KEY, AUTH_BOTH} and not (node.ssh_password or '').strip()
            code, output = run_ssh(
                host,
                user,
                script,
                str(PRIVATE_PATH) if use_key else '',
                node.ssh_password,
                port=int(node.ssh_port or 22),
                prefer_key=use_key,
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
    creds = parse_master_lines(output)
    url = (creds.get('MASTER_URL') or '').strip()
    token = (creds.get('MASTER_TOKEN') or '').strip()
    if code != 0 or creds.get('MASTER_ERROR') or not url or not token:
        message = (creds.get('MASTER_ERROR') or '').strip()
        if not message:
            visible = _visible_output(output)
            message = visible or f'установщик завершился с кодом {code}'
        _fail(session, node, _with_adopt(adopt_logs, message))
        return
    node.panel_url = normalize_panel_url(url)
    node.api_token = token
    node.public_host = public_host_from_url(node.panel_url) or host
    worker_state(session, node, 'install', 'Установка 3x-ui', 'ok', 'Панель установлена')
    node.install_state = 'done'
    node.enabled = True
    node.last_error = ''
    node.install_log = _with_adopt(adopt_logs, _success_log(output, creds))
    session.add(node)
    session.commit()
    session.refresh(node)
    try:
        from app.firewall import sync_node_firewall
        from app.provision import disable_node_subscription

        logs = [disable_node_subscription(node)]
        logs.extend(sync_node_firewall(node, set(), session))
    except Exception as exc:
        logs = [f'{node.name}: файрвол не обновился: {exc}']
        node.last_error = str(exc)[:240]
    extra = '\n'.join(line for line in logs if line)
    if extra:
        node.install_log = _clip(node.install_log + '\n' + extra)
        session.add(node)
        session.commit()


def interrupt_abandoned_installs(session: Session) -> None:
    """Поток установки живёт только в процессе мастера. После перезапуска он уже мёртв."""
    rows = session.exec(select(Node).where(Node.install_state == 'installing')).all()
    if not rows:
        return
    note = 'Установка прервалась: мастер перезапустился. Скрипт на сервере мог остановиться посередине.'
    for node in rows:
        node.install_state = 'failed'
        node.last_error = 'установка прервалась перезапуском'
        node.install_log = _clip((node.install_log or '').rstrip() + '\n' + note)
        session.add(node)
    session.commit()


def start_install(node_id: int) -> None:
    threading.Thread(
        target=_install_thread,
        args=(node_id,),
        name=f'xui-install-{node_id}',
        daemon=True,
    ).start()


def _install_thread(node_id: int) -> None:
    from app.database import engine

    with Session(engine) as session:
        try:
            apply_install_result(session, node_id)
        except Exception as exc:
            node = session.get(Node, node_id)
            if node is not None and (node.install_state or '') == 'installing':
                _fail(session, node, f'Установка прервалась: {exc}')
                return
        node = session.get(Node, node_id)
        if node is not None and (node.install_state or '') == 'done':
            try:
                from app.exporters import start_exporters
                from app.node_updates import check_updates

                check_updates(node)
                session.commit()
                start_exporters(session, node_id)
            except Exception as exc:
                session.rollback()
                node = session.get(Node, node_id)
                if node and node.exporter_state != 'installing':
                    from app.exporters import _remember
                    _remember(session, node, 'failed', str(exc))
