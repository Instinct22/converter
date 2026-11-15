"""Сверить ufw с входами сервера.

Открыты порты выбранных входов плюс служебные: SSH, 80 (продление
сертификата) и порт панели. Порт подписки 3x-ui не открываем: профиль
клиент забирает с Master. Любой другой порт в правилах ufw закрывается.
Правило, которое уже есть, второй раз не добавляется.
"""
from __future__ import annotations

import shlex
from urllib.parse import urlparse

from app.models import Node

_KEEP = {22, 80}


def panel_port(node: Node) -> int | None:
    parsed = urlparse((node.panel_url or '').strip())
    if parsed.port:
        return int(parsed.port)
    return None


def protected_ports(node: Node) -> set[int]:
    ports = set(_KEEP)
    ssh_port = int(getattr(node, 'ssh_port', 0) or 0)
    if ssh_port:
        ports.add(ssh_port)
    extra = panel_port(node)
    if extra:
        ports.add(extra)
    return ports


def wanted_ports(node: Node, open_ports: set[int]) -> set[int]:
    ports = set(protected_ports(node))
    for port in open_ports:
        number = int(port)
        if number > 0:
            ports.add(number)
    return ports


def display_ports(node: Node, inbound_ports: list[int]) -> tuple[str, str]:
    """Порты, которые Master держит открытыми: SSH, 80, панель и входы."""
    ports = sorted(wanted_ports(node, set(inbound_ports)))
    ssh = int(getattr(node, 'ssh_port', 0) or 22)
    panel = panel_port(node)
    roles: list[str] = []
    for port in ports:
        if port == ssh:
            roles.append(f'{port} SSH')
        elif port == 80:
            roles.append(f'{port} сертификат')
        elif panel and port == panel:
            roles.append(f'{port} панель')
        else:
            roles.append(f'{port} вход')
    label = ' '.join(str(port) for port in ports) or '—'
    state = 'сверено с ufw' if node.firewall_on else 'правило ещё не сверяли с ufw'
    title = ' · '.join(roles + [state, '2096 закрыт'])
    return label, title


def firewall_plan(node: Node, open_ports: set[int], current_ports: set[int]) -> list[tuple[str, int]]:
    """allow — порта нет в ufw, delete — в ufw есть порт, которого нет среди нужных."""
    wanted = wanted_ports(node, open_ports)
    current = {int(port) for port in current_ports if int(port) > 0}
    actions: list[tuple[str, int]] = []
    for port in sorted(wanted - current):
        actions.append(('allow', port))
    for port in sorted(current - wanted):
        actions.append(('delete', port))
    return actions


def _script(node: Node, open_ports: set[int]) -> str:
    wanted = sorted(wanted_ports(node, open_ports))
    keep = ' ' + ' '.join(str(port) for port in wanted) + ' '
    ssh_port = int(getattr(node, 'ssh_port', 0) or 22)
    allow_list = ' '.join(str(port) for port in wanted)
    return f'''set -eu
export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"
export DEBIAN_FRONTEND=noninteractive
if ! command -v ufw >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq ufw
  echo "! installed"
fi
keep={shlex.quote(keep)}
ssh_port={ssh_port}
if ! ufw status | awk '{{print $1}}' | grep -Eq "^${{ssh_port}}(/tcp)?$"; then
  ufw limit "$ssh_port/tcp" >/dev/null || ufw allow "$ssh_port/tcp" >/dev/null
fi
for _round in $(seq 1 40); do
  hit=$(ufw status numbered | awk -v keep="$keep" '
    /^\\[[[:space:]]*[0-9]+\\]/ {{
      n = $0
      sub(/^\\[[[:space:]]*/, "", n)
      num = n
      sub(/\\].*/, "", num)
      rest = n
      sub(/^[0-9]+\\][[:space:]]*/, "", rest)
      split(rest, a, /[[:space:]]+/)
      token = a[1]
      if (token ~ /^\\(v6\\)$/) next
      port = token
      sub(/\\/.*/, "", port)
      if (port !~ /^[0-9]+$/) next
      if (index(keep, " " port " ") == 0) {{
        print num " " port
        exit
      }}
    }}
  ')
  [ -n "$hit" ] || break
  num=${{hit%% *}}
  port=${{hit#* }}
  ufw --force delete "$num" >/dev/null
  echo "- $port"
done
for port in {allow_list}; do
  if ufw status | awk '{{print $1}}' | grep -Eq "^${{port}}(/tcp)?$"; then
    continue
  fi
  if [ "$port" = "$ssh_port" ]; then
    ufw limit "$port/tcp" >/dev/null
  else
    ufw allow "$port/tcp" >/dev/null
  fi
  echo "+ $port"
done
if ufw status | head -n 1 | grep -q inactive; then
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw --force enable >/dev/null
  echo "! enabled"
fi
'''


def _summary(name: str, output: str) -> list[str]:
    opened: list[str] = []
    closed: list[str] = []
    enabled = False
    installed = False
    for line in output.splitlines():
        if line.startswith('+ '):
            port = line[2:].strip()
            if port not in opened:
                opened.append(port)
        elif line.startswith('- '):
            port = line[2:].strip()
            if port not in closed:
                closed.append(port)
        elif line.strip() == '! enabled':
            enabled = True
        elif line.strip() == '! installed':
            installed = True
    bits = [f'{port} открыт' for port in opened]
    bits.extend(f'{port} закрыт' for port in closed)
    if installed:
        bits.append('ufw поставлен')
    if enabled:
        bits.append('файрвол включён')
    if not bits:
        bits.append('лишних портов нет')
    return [f'{name}: файрвол — ' + ', '.join(bits)]


def _remember(node: Node, session, on: bool, note: str) -> None:
    node.firewall_on = bool(on)
    node.firewall_note = (note or '')[:240]
    if session is not None:
        session.add(node)
        session.commit()


def _ssh(node: Node):
    from app.ssh_access import open_client

    return open_client(node, timeout=20)


def _run(node: Node, command: str, timeout: int) -> tuple[int, str, str]:
    client = _ssh(node)
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace').strip()
    finally:
        client.close()
    return code, out, err


def sync_node_firewall(node: Node, open_ports: set[int], session=None) -> list[str]:
    from app.ssh_access import can_ssh

    if not can_ssh(node):
        _remember(node, session, False, 'нет входа SSH')
        return [f'{node.name}: файрвол не сверил, нет входа SSH']
    host = (node.public_host or '').strip() or (urlparse(node.panel_url or '').hostname or '')
    if not host:
        _remember(node, session, False, 'нет адреса сервера')
        return [f'{node.name}: файрвол не сверил, нет адреса сервера']
    try:
        import paramiko  # noqa: F401
    except ImportError:
        _remember(node, session, False, 'нет библиотеки SSH')
        return [f'{node.name}: файрвол не сверил, нет библиотеки SSH']
    try:
        code, out, err = _run(node, _script(node, open_ports), 180)
    except Exception as exc:
        _remember(node, session, False, str(exc)[:240])
        return [f'{node.name}: файрвол не обновился: {exc}']
    if code != 0:
        detail = err or out.strip() or f'код {code}'
        _remember(node, session, False, detail[:240])
        return [f'{node.name}: файрвол не обновился: {detail[:300]}']
    logs = _summary(node.name, out)
    note = logs[0].split('файрвол — ', 1)[-1]
    _remember(node, session, True, note)
    return logs
