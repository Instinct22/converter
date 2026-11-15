"""Один ключ на весь флот.

Закрытый ключ лежит только в data/ssh. В базу и в страницу он не попадает.
Пароль на ноде хранится, пока вход этим ключом не проверен. После проверки
парольный SSH на сервере выключается, и пароль из карточки стирается.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
from dataclasses import dataclass

from app.models import Node
from app.settings import DATA_DIR

KEY_DIR = DATA_DIR / 'ssh'
PRIVATE_PATH = KEY_DIR / 'master_ed25519'
PUBLIC_PATH = KEY_DIR / 'master_ed25519.pub'
KEY_COMMENT = 'master@fleet'

AUTH_KEY = 'key'
AUTH_BOTH = 'both'
AUTH_PASSWORD = 'password'
AUTH_NONE = 'none'
_AUTHS = {AUTH_KEY, AUTH_BOTH, AUTH_PASSWORD, AUTH_NONE}
_PUB_BODY = re.compile(r'^[A-Za-z0-9+/=]+$')


@dataclass
class AdoptResult:
    ok: bool
    auth: str
    logs: list[str]


def resolved_auth(node: Node) -> str:
    stored = (getattr(node, 'ssh_auth', '') or '').strip()
    if stored in _AUTHS:
        return stored
    if (getattr(node, 'ssh_password', '') or '').strip():
        return AUTH_PASSWORD
    return AUTH_NONE


def key_file_exists() -> bool:
    return PRIVATE_PATH.is_file()


def can_ssh(node: Node) -> bool:
    auth = resolved_auth(node)
    password = (getattr(node, 'ssh_password', '') or '').strip()
    if auth == AUTH_KEY:
        return key_file_exists()
    if auth == AUTH_BOTH:
        return key_file_exists() or bool(password)
    if auth == AUTH_PASSWORD:
        return bool(password)
    return False


def ensure_fleet_key() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    if PRIVATE_PATH.is_file():
        if not PUBLIC_PATH.is_file():
            _write_secret(PUBLIC_PATH, _public_from_private() + '\n')
        return
    _generate()


def public_key_line() -> str:
    ensure_fleet_key()
    line = PUBLIC_PATH.read_text(encoding='utf-8').strip()
    if not valid_public_key(line):
        raise RuntimeError('публичный ключ флота повреждён')
    return line


def fingerprint() -> str:
    body = public_key_line().split()[1]
    digest = hashlib.sha256(base64.b64decode(body)).digest()
    return 'SHA256:' + base64.b64encode(digest).decode('ascii').rstrip('=')


def valid_public_key(line: str) -> bool:
    parts = (line or '').strip().split()
    return len(parts) >= 2 and parts[0] == 'ssh-ed25519' and bool(_PUB_BODY.fullmatch(parts[1]))


def install_pubkey_script(public_line: str) -> str:
    if not valid_public_key(public_line):
        raise ValueError('публичный ключ флота повреждён')
    quoted = shlex.quote(public_line.strip())
    return f'''set -eu
umask 077
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 700 "$HOME/.ssh"
chmod 600 "$HOME/.ssh/authorized_keys"
pub={quoted}
grep -qxF "$pub" "$HOME/.ssh/authorized_keys" || printf '%s\\n' "$pub" >> "$HOME/.ssh/authorized_keys"
echo MASTER_PUB_OK
'''


def lockdown_script() -> str:
    return r'''set -eu
export PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
drop=/etc/ssh/sshd_config.d/99-master-key.conf
mkdir -p /etc/ssh/sshd_config.d
cat > "$drop" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
chmod 644 "$drop"
auth=$(sshd -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{print $2; exit}')
if [ "$auth" != "no" ]; then
  cfg=/etc/ssh/sshd_config
  tmp=$(mktemp)
  cat > "$tmp" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
  cat "$cfg" >> "$tmp"
  mv "$tmp" "$cfg"
  chmod 644 "$cfg"
  auth=$(sshd -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{print $2; exit}')
fi
sshd -t
echo "PASSWORD_AUTH ${auth:-unknown}"
systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || true
'''


def run_remote(
    host: str,
    user: str,
    port: int,
    script: str,
    *,
    password: str = '',
    key_path: str = '',
    timeout: int = 30,
) -> tuple[int, str, str]:
    client = _connect_host(host, user, port, password=password, key_path=key_path, timeout=timeout)
    try:
        stdin, stdout, stderr = client.exec_command('bash -s', timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        client.close()


def open_client(node: Node, *, mode: str = 'auto', timeout: int = 20):
    auth = resolved_auth(node)
    password = (getattr(node, 'ssh_password', '') or '').strip()
    host, user, port = _target(node)
    if mode == 'password':
        if not password:
            raise RuntimeError('нет SSH-пароля')
        return _connect_host(host, user, port, password=password, timeout=timeout)
    if mode == 'key':
        if not key_file_exists():
            raise RuntimeError('ключа флота нет')
        return _connect_host(host, user, port, key_path=str(PRIVATE_PATH), timeout=timeout)
    if auth in {AUTH_KEY, AUTH_BOTH} and key_file_exists():
        try:
            return _connect_host(host, user, port, key_path=str(PRIVATE_PATH), timeout=timeout)
        except Exception:
            if auth == AUTH_BOTH and password:
                return _connect_host(host, user, port, password=password, timeout=timeout)
            raise
    if password:
        return _connect_host(host, user, port, password=password, timeout=timeout)
    raise RuntimeError('нет входа SSH')


def run_on_node(node: Node, command: str, timeout: int, *, mode: str = 'auto') -> tuple[int, str, str]:
    client = open_client(node, mode=mode, timeout=min(timeout, 25))
    try:
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        return code, out, err
    finally:
        client.close()


def adopt_node(node: Node, session=None, runner=None) -> AdoptResult:
    """Поставить ключ флота и выключить пароль только после входа ключом."""
    ensure_fleet_key()
    public = public_key_line()
    password = (getattr(node, 'ssh_password', '') or '').strip()
    name = node.name or 'сервер'

    def call(mode: str, command: str, timeout: int = 30) -> tuple[int, str, str]:
        if runner is not None:
            return runner(mode, command)
        return run_on_node(node, command, timeout, mode=mode)

    def save(auth: str, keep_password: bool) -> None:
        node.ssh_auth = auth
        if not keep_password:
            node.ssh_password = ''
        if session is not None:
            session.add(node)
            session.commit()

    key_ok = _key_login(call)
    if not key_ok:
        if not password:
            save(AUTH_NONE, True)
            return AdoptResult(False, AUTH_NONE, [f'{name}: нет пароля, ключ флота не подходит'])
        try:
            code, out, err = call('password', install_pubkey_script(public), 40)
        except Exception as exc:
            save(AUTH_PASSWORD, True)
            return AdoptResult(False, AUTH_PASSWORD, [f'{name}: не удалось зайти по паролю: {exc}'])
        if code != 0 or 'MASTER_PUB_OK' not in (out or ''):
            save(AUTH_PASSWORD, True)
            detail = ((err or out or f'код {code}').strip())[:200]
            return AdoptResult(False, AUTH_PASSWORD, [f'{name}: ключ не записался: {detail}'])
        key_ok = _key_login(call)
        if not key_ok:
            save(AUTH_PASSWORD, True)
            return AdoptResult(False, AUTH_PASSWORD, [f'{name}: ключ записан, вход им не открылся, пароль оставлен'])

    try:
        code, out, err = call('key', lockdown_script(), 40)
    except Exception as exc:
        save(AUTH_BOTH, True)
        return AdoptResult(False, AUTH_BOTH, [f'{name}: вход по ключу есть, пароль выключить не удалось: {exc}'])
    if code != 0 or 'PASSWORD_AUTH no' not in (out or ''):
        save(AUTH_BOTH, True)
        detail = ((err or out or f'код {code}').strip())[:200]
        return AdoptResult(False, AUTH_BOTH, [f'{name}: вход по ключу есть, пароль ещё включён: {detail}'])
    save(AUTH_KEY, False)
    return AdoptResult(True, AUTH_KEY, [f'{name}: парольный вход выключен, пароль удалён из Master'])


def _key_login(call) -> bool:
    try:
        code, out, _err = call('key', 'echo MASTER_KEY_OK', 20)
    except Exception:
        return False
    return code == 0 and 'MASTER_KEY_OK' in (out or '')


def _target(node: Node) -> tuple[str, str, int]:
    from urllib.parse import urlparse

    host = (getattr(node, 'public_host', '') or '').strip()
    if not host:
        host = urlparse(getattr(node, 'panel_url', '') or '').hostname or ''
    if not host:
        raise RuntimeError('нет адреса сервера')
    user = (getattr(node, 'ssh_user', '') or 'root').strip() or 'root'
    port = int(getattr(node, 'ssh_port', 0) or 22)
    return host, user, port


def _connect_host(host: str, user: str, port: int, *, password: str = '', key_path: str = '', timeout: int = 20):
    import paramiko

    if not host:
        raise RuntimeError('нет адреса сервера')
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    wait = min(25, max(8, int(timeout)))
    kwargs = {
        'hostname': host,
        'port': int(port or 22),
        'username': user or 'root',
        'timeout': wait,
        'banner_timeout': wait,
        'auth_timeout': wait,
        'allow_agent': False,
        'look_for_keys': False,
    }
    if key_path:
        kwargs['pkey'] = paramiko.Ed25519Key.from_private_key_file(key_path)
    elif password:
        kwargs['password'] = password
    else:
        raise RuntimeError('нет ключа и пароля')
    client.connect(**kwargs)
    return client


def _generate() -> None:
    import io

    import paramiko
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_secret(PRIVATE_PATH, raw)
    key = paramiko.Ed25519Key.from_private_key(io.StringIO(raw.decode('ascii')))
    _write_secret(PUBLIC_PATH, f'ssh-ed25519 {key.get_base64()} {KEY_COMMENT}\n')


def _public_from_private() -> str:
    import paramiko

    key = paramiko.Ed25519Key.from_private_key_file(str(PRIVATE_PATH))
    return f'ssh-ed25519 {key.get_base64()} {KEY_COMMENT}'


def _write_secret(path, data: str | bytes) -> None:
    payload = data.encode('ascii') if isinstance(data, str) else data
    path.write_bytes(payload)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
