"""Сверить ufw с входами сервера.

Открыты порты выбранных входов плюс служебные: SSH, 80 (продление
сертификата), порт панели и порт подписки. Любой другой порт в правилах
ufw закрывается. Правило, которое уже есть, второй раз не добавляется.
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
    sub_port = int(getattr(node, 'sub_port', 0) or 0)
    if sub_port:
        ports.add(sub_port)
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
keep={shlex.quote(keep)}
ssh_port={ssh_port}
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
    bits = [f'{port} открыт' for port in opened]
    bits.extend(f'{port} закрыт' for port in closed)
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
    import paramiko

    host = (node.public_host or '').strip() or (urlparse(node.panel_url or '').hostname or '')
    user = (getattr(node, 'ssh_user', '') or 'root').strip() or 'root'
    ssh_port = int(getattr(node, 'ssh_port', 0) or 22)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host,
        port=ssh_port,
        username=user,
        password=node.ssh_password,
        timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


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


def probe_node_firewall(node: Node, session=None) -> list[str]:
    """Один заход по SSH: ufw отвечает и включён — «вкл», иначе «выкл»."""
    if not (getattr(node, 'ssh_password', '') or '').strip():
        _remember(node, session, False, 'нет SSH-пароля')
        return [f'{node.name}: файрвол выкл, нет SSH-пароля']
    host = (node.public_host or '').strip() or (urlparse(node.panel_url or '').hostname or '')
    if not host:
        _remember(node, session, False, 'нет адреса сервера')
        return [f'{node.name}: файрвол выкл, нет адреса сервера']
    try:
        import paramiko  # noqa: F401
    except ImportError:
        _remember(node, session, False, 'нет библиотеки SSH')
        return [f'{node.name}: файрвол выкл, нет библиотеки SSH']
    try:
        code, out, err = _run(node, 'ufw status', 25)
    except Exception as exc:
        _remember(node, session, False, str(exc)[:240])
        return [f'{node.name}: файрвол выкл: {exc}']
    if code != 0:
        detail = err or out.strip() or f'код {code}'
        _remember(node, session, False, detail[:240])
        return [f'{node.name}: файрвол выкл: {detail[:300]}']
    active = 'inactive' not in out.lower().split('\n', 1)[0].lower()
    if not active:
        _remember(node, session, False, 'ufw выключен')
        return [f'{node.name}: файрвол выкл, ufw выключен']
    _remember(node, session, True, 'ufw отвечает')
    return [f'{node.name}: файрвол вкл']


def sync_node_firewall(node: Node, open_ports: set[int], session=None) -> list[str]:
    if not (getattr(node, 'ssh_password', '') or '').strip():
        _remember(node, session, False, 'нет SSH-пароля')
        return [f'{node.name}: файрвол не сверил, нет SSH-пароля']
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
        code, out, err = _run(node, _script(node, open_ports), 60)
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
