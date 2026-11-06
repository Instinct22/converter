"""Открыть и закрыть порты входов в ufw на самом сервере.

22, 80, порт панели и порт подписки не закрываем: через них Master
ходит на сервер.
"""
from __future__ import annotations

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


def firewall_actions(node: Node, open_ports: set[int], close_ports: set[int]) -> list[tuple[str, int]]:
    """allow — открыть, delete — снять правило. Служебные порты не закрываются."""
    keep = protected_ports(node)
    actions: list[tuple[str, int]] = []
    opening = {int(port) for port in open_ports if int(port) > 0}
    for port in sorted(opening):
        actions.append(('allow', port))
    for port in sorted(int(port) for port in close_ports if int(port) > 0):
        if port in keep or port in opening:
            continue
        actions.append(('delete', port))
    return actions


def _script(actions: list[tuple[str, int]]) -> str:
    lines = ['set -eu']
    for kind, port in actions:
        if kind == 'allow':
            lines.append(
                f"if ! ufw status | awk '{{print $1}}' | grep -qx '{port}/tcp'; then ufw allow {port}/tcp; fi"
            )
        else:
            lines.append(
                f"for _try in 1 2 3 4; do ufw status | awk '{{print $1}}' | grep -qx '{port}/tcp' || break; ufw --force delete allow {port}/tcp >/dev/null || break; done"
            )
    lines.append("ufw status | awk '{print $1}'")
    return '\n'.join(lines)


def sync_node_firewall(node: Node, open_ports: set[int], close_ports: set[int]) -> list[str]:
    actions = firewall_actions(node, open_ports, close_ports)
    if not actions:
        return []
    if not (getattr(node, 'ssh_password', '') or '').strip():
        ports = ', '.join(str(port) for _kind, port in actions)
        return [f'{node.name}: файрвол не трогал ({ports}), нет SSH-пароля']
    host = (node.public_host or '').strip() or (urlparse(node.panel_url or '').hostname or '')
    if not host:
        return [f'{node.name}: файрвол не трогал, нет адреса сервера']
    try:
        import paramiko
    except ImportError:
        return [f'{node.name}: файрвол не трогал, нет библиотеки SSH']
    user = (getattr(node, 'ssh_user', '') or 'root').strip() or 'root'
    ssh_port = int(getattr(node, 'ssh_port', 0) or 22)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host,
            port=ssh_port,
            username=user,
            password=node.ssh_password,
            timeout=20,
            look_for_keys=False,
            allow_agent=False,
        )
        _stdin, stdout, stderr = client.exec_command(_script(actions), timeout=40)
        stdout.channel.recv_exit_status()
        err = stderr.read().decode('utf-8', 'replace').strip()
    except Exception as exc:
        return [f'{node.name}: файрвол не обновился: {exc}']
    finally:
        client.close()
    if err:
        return [f'{node.name}: файрвол: {err[:300]}']
    bits = []
    for kind, port in actions:
        bits.append(f'{port} открыт' if kind == 'allow' else f'{port} закрыт')
    return [f'{node.name}: файрвол — ' + ', '.join(bits)]
