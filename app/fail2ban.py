"""Поставить fail2ban и прочитать баны по SSH.

Одно правило на весь флот: подбор SSH и повторные баны.
Порты клиентов (443 и остальные входы) не сторожим.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.firewall import _run
from app.models import Node
from app.settings import settings

_STATE_OK = {'protecting', 'missing', 'error', 'no_ssh'}
_IP = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9A-Fa-f:]+$')


@dataclass
class GuardView:
    state: str
    banned: int
    day: int
    note: str
    installed: bool = False


@dataclass
class BanView:
    ip: str
    jail: str
    reason: str
    failures: int
    times: int
    until: str


def clean_ip_token(value: str) -> str:
    token = (value or '').strip()
    if re.fullmatch(r'[0-9A-Fa-f:.]+(?:/\d{1,3})?', token):
        return token
    return ''


def ignore_line() -> str:
    parts = ['127.0.0.1/8', '::1']
    master = clean_ip_token(settings.master_ip)
    if master and master not in parts:
        parts.append(master)
    return ' '.join(parts)


def jail_config(ssh_port: int, ignore: str | None = None) -> str:
    port = int(ssh_port or 22)
    skipped = ignore if ignore is not None else ignore_line()
    return (
        '[DEFAULT]\n'
        f'ignoreip = {skipped}\n'
        '\n'
        '[sshd]\n'
        'enabled = true\n'
        f'port = {port}\n'
        'maxretry = 4\n'
        'findtime = 10m\n'
        'bantime = 1h\n'
        '\n'
        '[recidive]\n'
        'enabled = true\n'
        'logpath = /var/log/fail2ban.log\n'
        'bantime = 1w\n'
        'findtime = 1d\n'
        'maxretry = 3\n'
    )


def reason_for(jail: str) -> str:
    if jail == 'sshd':
        return 'подбор SSH'
    if jail == 'recidive':
        return 'повторные баны'
    return jail or 'бан'


def until_label(seconds: int) -> str:
    left = int(seconds)
    if left <= 0:
        return 'истекает'
    if left < 3600:
        return f'ещё {max(1, left // 60)} мин'
    if left < 86400:
        return f'ещё {max(1, left // 3600)} ч'
    return f'ещё {max(1, left // 86400)} дн'


def valid_ban_ip(value: str) -> bool:
    return bool(_IP.fullmatch((value or '').strip()))


def parse_guard_output(text: str) -> GuardView:
    view = GuardView(state='error', banned=0, day=0, note='')
    for raw in (text or '').splitlines():
        line = raw.strip()
        if line == '! installed':
            view.installed = True
            continue
        if line.startswith('STATE '):
            state = line.split(' ', 1)[1].strip()
            view.state = state if state in _STATE_OK else 'error'
        elif line.startswith('BANNED '):
            view.banned = _int_token(line)
        elif line.startswith('DAY '):
            view.day = _int_token(line)
        elif line.startswith('NOTE '):
            view.note = line[5:].strip()[:240]
    return view


def parse_ban_lines(text: str) -> list[BanView]:
    rows: list[BanView] = []
    for raw in (text or '').splitlines():
        if not raw.startswith('BAN\t'):
            continue
        parts = raw.split('\t')
        if len(parts) < 6:
            continue
        ip, jail = parts[1].strip(), parts[2].strip()
        if not valid_ban_ip(ip):
            continue
        rows.append(BanView(
            ip=ip,
            jail=jail,
            reason=reason_for(jail),
            times=_safe_int(parts[3]),
            failures=_safe_int(parts[5]),
            until=until_label(_safe_int(parts[4])),
        ))
    return rows


def _int_token(line: str) -> int:
    bits = line.split()
    if len(bits) < 2:
        return 0
    return _safe_int(bits[1])


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _remember(node: Node, session, view: GuardView) -> None:
    node.fail2ban_state = view.state
    node.fail2ban_banned = int(view.banned or 0)
    node.fail2ban_day = int(view.day or 0)
    node.fail2ban_note = (view.note or '')[:240]
    if session is not None:
        session.add(node)
        session.commit()


def _status_python() -> str:
    return r'''python3 - <<'PY'
import json, sqlite3, subprocess, time
try:
    def banned(name):
        try:
            out = subprocess.check_output(["fail2ban-client", "status", name], text=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            return None, exc.output or ""
        return 0, out
    ssh_code, ssh_out = banned("sshd")
    if ssh_code is None:
        tail = (ssh_out or "jail sshd не читается").strip().splitlines()
        print("STATE error")
        print("BANNED 0")
        print("DAY 0")
        print("NOTE " + (tail[-1] if tail else "jail sshd не читается")[:200])
        raise SystemExit
    banned_n = 0
    day = 0
    note = "ok"
    try:
        con = sqlite3.connect("/var/lib/fail2ban/fail2ban.sqlite3")
        now = int(time.time())
        banned_n = con.execute(
            "SELECT COUNT(DISTINCT ip) FROM bips WHERE timeofban + bantime > ?",
            (now,),
        ).fetchone()[0] or 0
        day = con.execute(
            "SELECT COUNT(*) FROM bans WHERE timeofban > ?",
            (now - 86400,),
        ).fetchone()[0] or 0
        cols = [row[1] for row in con.execute("PRAGMA table_info(bips)")]
        if "data" in cols:
            query = "SELECT ip, jail, bancount, timeofban, bantime, data FROM bips WHERE timeofban + bantime > ? ORDER BY timeofban DESC"
        else:
            query = "SELECT ip, jail, bancount, timeofban, bantime, '' FROM bips WHERE timeofban + bantime > ? ORDER BY timeofban DESC"
        for ip, jail, times, started, span, data in con.execute(query, (now,)):
            failures = 0
            if data:
                try:
                    payload = json.loads(data)
                    failures = int(payload.get("failures") or 0)
                except Exception:
                    failures = 0
            left = int(started) + int(span) - now
            print(f"BAN\t{ip}\t{jail}\t{int(times or 0)}\t{left}\t{failures}")
    except Exception:
        note = "счётчик истории недоступен"
    print("STATE protecting")
    print("BANNED " + str(int(banned_n)))
    print("DAY " + str(int(day)))
    print("NOTE " + note)
except Exception as exc:
    print("STATE error")
    print("BANNED 0")
    print("DAY 0")
    print("NOTE " + str(exc)[:200])
PY
'''


def _read_script() -> str:
    return f'''set -eu
export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"
if ! command -v fail2ban-client >/dev/null 2>&1; then
  echo "STATE missing"
  echo "BANNED 0"
  echo "DAY 0"
  echo "NOTE fail2ban не установлен"
  exit 0
fi
if [ "$(systemctl is-active fail2ban 2>/dev/null || true)" != "active" ]; then
  echo "STATE error"
  echo "BANNED 0"
  echo "DAY 0"
  echo "NOTE служба fail2ban не запущена"
  exit 0
fi
{_status_python()}
'''


def _install_script(node: Node) -> str:
    config = jail_config(int(getattr(node, 'ssh_port', 0) or 22))
    return f'''set -eu
export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"
export DEBIAN_FRONTEND=noninteractive
if ! command -v fail2ban-client >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq fail2ban
  echo "! installed"
fi
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/master.local <<'EOF'
{config}EOF
systemctl enable fail2ban >/dev/null
systemctl restart fail2ban
sleep 1
{_status_python()}
'''


def _log(node: Node, view: GuardView) -> str:
    labels = {
        'protecting': 'защищает',
        'missing': 'не установлен',
        'no_ssh': 'нет SSH',
        'error': 'ошибка',
    }
    label = labels.get(view.state, view.state)
    bits = [label]
    if view.installed:
        bits.append('fail2ban поставлен')
    if view.state == 'protecting':
        bits.append(f'в бане {view.banned}')
        bits.append(f'за сутки {view.day}')
    if view.note and view.note != 'ok':
        bits.append(view.note)
    return f'{node.name}: ' + ', '.join(bits)


def sync_node_guard(node: Node, session=None, install: bool = False) -> list[str]:
    if not (getattr(node, 'ssh_password', '') or '').strip():
        view = GuardView(state='no_ssh', banned=0, day=0, note='нет SSH-пароля')
        _remember(node, session, view)
        return [_log(node, view)]
    host = (node.public_host or '').strip()
    if not host:
        view = GuardView(state='error', banned=0, day=0, note='нет адреса сервера')
        _remember(node, session, view)
        return [_log(node, view)]
    script = _install_script(node) if install else _read_script()
    try:
        code, out, err = _run(node, script, 180 if install else 40)
    except Exception as exc:
        view = GuardView(state='error', banned=0, day=0, note=str(exc)[:240])
        _remember(node, session, view)
        return [_log(node, view)]
    view = parse_guard_output(out)
    if code != 0 and view.state == 'error' and not view.note:
        view.note = (err or out or f'код {code}')[:240]
    if view.installed and view.note == 'ok':
        view.note = 'правило записано'
    _remember(node, session, view)
    return [_log(node, view)]


def read_bans(node: Node) -> tuple[GuardView, list[BanView]]:
    if not (getattr(node, 'ssh_password', '') or '').strip():
        return GuardView(state='no_ssh', banned=0, day=0, note='нет SSH-пароля'), []
    code, out, err = _run(node, _read_script(), 40)
    view = parse_guard_output(out)
    if code != 0 and not view.note:
        view.note = (err or f'код {code}')[:240]
        view.state = 'error'
    return view, parse_ban_lines(out)


def unban(node: Node, ip: str = '', clear_all: bool = False) -> list[str]:
    if clear_all:
        script = (
            'set -eu\n'
            'export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"\n'
            'fail2ban-client unban --all\n'
        )
    else:
        if not valid_ban_ip(ip):
            raise ValueError('не похоже на адрес')
        safe = ip.strip()
        script = (
            'set -eu\n'
            'export PATH="/usr/local/sbin:/usr/sbin:/sbin:$PATH"\n'
            f'fail2ban-client set sshd unbanip {safe} >/dev/null 2>&1 || true\n'
            f'fail2ban-client set recidive unbanip {safe} >/dev/null 2>&1 || true\n'
        )
    code, out, err = _run(node, script, 30)
    if code != 0:
        detail = (err or out or f'код {code}')[:240]
        raise RuntimeError(detail)
    if clear_all:
        return [f'{node.name}: все баны сняты']
    return [f'{node.name}: {ip.strip()} снят с бана']
