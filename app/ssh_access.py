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
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from app.models import Node
from app.settings import DATA_DIR, settings

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


class HostIdentityError(RuntimeError):
    pass


class ConfirmHostKey(HostIdentityError):
    def __init__(self, address, key):
        super().__init__(f'Подтвердите ключ SSH для {address}')
        self.address = address
        self.algorithm = key.get_name()
        self.fingerprint = key.fingerprint


@dataclass
class AdoptResult:
    ok: bool
    auth: str
    logs: list[str]
    identity_error: bool = False


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


def lockdown_script(ssh_port: int = 22, master_ip: str = '') -> str:
    port = int(ssh_port or 22)
    master = (master_ip or '').strip()
    allow = ''
    if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', master):
        allow = (
            'if command -v ufw >/dev/null 2>&1; then\n'
            f'  ufw insert 1 allow from {master} to any port {port} proto tcp >/dev/null 2>&1 || true\n'
            'fi\n'
        )
    return f'''set -eu
export PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
{allow}drop=/etc/ssh/sshd_config.d/99-master-key.conf
mkdir -p /etc/ssh/sshd_config.d
cat > "$drop" <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
EOF
chmod 644 "$drop"
auth=$(sshd -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{{print $2; exit}}')
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
  auth=$(sshd -T 2>/dev/null | awk 'tolower($1)=="passwordauthentication"{{print $2; exit}}')
fi
sshd -t
printf 'PASSWORD_AUTH %s\\n' "${{auth:-unknown}}" > /run/master-ssh-auth
cat /run/master-ssh-auth
sleep 1
systemctl reload ssh >/dev/null 2>&1 || systemctl reload sshd >/dev/null 2>&1 || service ssh reload >/dev/null 2>&1 || true
'''


def key_lockdown_script(ssh_port: int = 22, master_ip: str = '') -> str:
    """Одна сессия: доказать вход ключом и только потом выключить пароль."""
    return 'echo MASTER_KEY_OK\n' + lockdown_script(ssh_port, master_ip)


def run_remote(
    host: str,
    user: str,
    port: int,
    script: str,
    *,
    password: str = '',
    key_path: str = '',
    timeout: int = 30,
    on_line=None,
) -> tuple[int, str, str]:
    client = _connect_host(host, user, port, password=password, key_path=key_path, timeout=timeout)
    try:
        stdin, stdout, stderr = client.exec_command('bash -s', timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        err_box: list[str] = []

        def _drain_err() -> None:
            err_box.append(stderr.read().decode('utf-8', 'replace'))

        import threading

        drain = threading.Thread(target=_drain_err, daemon=True)
        drain.start()
        chunks: list[str] = []
        while True:
            raw = stdout.readline()
            if not raw:
                break
            text = raw.decode('utf-8', 'replace') if isinstance(raw, bytes) else raw
            chunks.append(text)
            if on_line is not None:
                on_line(text.rstrip('\n'))
        drain.join(timeout=5)
        code = stdout.channel.recv_exit_status()
        return code, ''.join(chunks), err_box[0] if err_box else ''
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
        except HostIdentityError:
            raise
        except Exception:
            if auth == AUTH_BOTH and password:
                return _connect_host(host, user, port, password=password, timeout=timeout)
            raise
    if password:
        return _connect_host(host, user, port, password=password, timeout=timeout)
    raise RuntimeError('нет входа SSH')


def run_on_node(node: Node, command: str, timeout: int, *, mode: str = 'auto') -> tuple[int, str, str]:
    client = _open_with_retry(node, mode=mode, timeout=min(timeout, 20))
    try:
        return _exec_bash(client, command, timeout)
    finally:
        client.close()


def _open_with_retry(node: Node, *, mode: str, timeout: int):
    """ufw limit режет частые новые входы с одного адреса. Подождать и повторить."""
    delay = 0
    last = None
    for _attempt in range(4):
        if delay:
            time.sleep(delay)
        try:
            return open_client(node, mode=mode, timeout=timeout)
        except Exception as exc:
            last = exc
            if not _retryable_connect(exc):
                raise
            delay = 12
    raise last


def _retryable_connect(exc: Exception) -> bool:
    text = str(exc).lower()
    return 'unable to connect' in text or 'timed out' in text or 'connection refused' in text or 'connection reset' in text


def _exec_bash(client, script: str, timeout: int) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command('bash -s', timeout=timeout)
    stdin.write(script if script.endswith('\n') else script + '\n')
    stdin.channel.shutdown_write()
    out = ''
    err = ''
    try:
        out = stdout.read().decode('utf-8', 'replace')
    except Exception:
        out = ''
    try:
        err = stderr.read().decode('utf-8', 'replace')
    except Exception:
        err = ''
    try:
        code = stdout.channel.recv_exit_status()
    except Exception:
        code = 0 if 'PASSWORD_AUTH no' in out else 1
    return code, out, err


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

    def finish_key_session(code: int, out: str, err: str, connect_error: str = '') -> AdoptResult | None:
        text = out or ''
        if 'MASTER_KEY_OK' in text and 'PASSWORD_AUTH no' in text:
            save(AUTH_KEY, False)
            return AdoptResult(True, AUTH_KEY, [f'{name}: парольный вход выключен, пароль удалён из Master'])
        if 'MASTER_KEY_OK' not in text:
            return None
        save(AUTH_BOTH, True)
        detail = ((err or text or connect_error or f'код {code}').strip())[:200]
        return AdoptResult(False, AUTH_BOTH, [f'{name}: вход по ключу есть, пароль ещё включён: {detail}'])

    script = key_lockdown_script(int(getattr(node, 'ssh_port', 0) or 22), settings.master_ip)
    try:
        code, out, err = call('key', script, 70)
    except HostIdentityError as exc:
        return AdoptResult(False, resolved_auth(node), [f'{name}: {exc}'], identity_error=True)
    except Exception as exc:
        code, out, err = 1, '', str(exc)
    done = finish_key_session(code, out, err)
    if done is not None:
        return done
    if not password:
        save(AUTH_NONE, True)
        detail = (err or 'ключ флота не подходит').strip()[:200]
        return AdoptResult(False, AUTH_NONE, [f'{name}: нет пароля, {detail}'])
    try:
        code, out, err = call('password', install_pubkey_script(public), 40)
    except HostIdentityError as exc:
        return AdoptResult(False, resolved_auth(node), [f'{name}: {exc}'], identity_error=True)
    except Exception as exc:
        save(AUTH_PASSWORD, True)
        return AdoptResult(False, AUTH_PASSWORD, [f'{name}: не удалось зайти по паролю: {exc}'])
    if code != 0 or 'MASTER_PUB_OK' not in (out or ''):
        save(AUTH_PASSWORD, True)
        detail = ((err or out or f'код {code}').strip())[:200]
        return AdoptResult(False, AUTH_PASSWORD, [f'{name}: ключ не записался: {detail}'])
    try:
        code, out, err = call('key', script, 70)
    except HostIdentityError as exc:
        return AdoptResult(False, resolved_auth(node), [f'{name}: {exc}'], identity_error=True)
    except Exception as exc:
        save(AUTH_BOTH, True)
        return AdoptResult(False, AUTH_BOTH, [f'{name}: ключ записан, повторный вход не открылся: {exc}'])
    done = finish_key_session(code, out, err)
    if done is not None:
        return done
    save(AUTH_PASSWORD, True)
    return AdoptResult(False, AUTH_PASSWORD, [f'{name}: ключ записан, вход им не открылся, пароль оставлен'])


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


def host_key_name(host, port):
    return host if port == 22 else f'[{host}]:{port}'


def _pin_path(address):
    return KEY_DIR / 'confirmed_hosts' / hashlib.sha256(address.encode()).hexdigest()


def trusted_ssh_client(host, port):
    import paramiko

    client = paramiko.SSHClient()
    try:
        client.load_host_keys(str(Path.home() / '.ssh' / 'known_hosts'))
    except (FileNotFoundError, PermissionError):
        pass  # The per-user OpenSSH file is optional.
    hosts_file = KEY_DIR / 'known_hosts'
    if hosts_file.is_file():
        client.load_host_keys(str(hosts_file))
    address = host_key_name(host, port)
    if not client.get_host_keys().lookup(address):
        pin = _pin_path(address)
        if pin.is_file():
            client.load_host_keys(str(pin))

    class RejectUnknownHost(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            raise HostIdentityError(f'Для {hostname} нет проверенного ключа в known_hosts')

    client.set_missing_host_key_policy(RejectUnknownHost())
    return client


def _read_server_key(host, port):
    import paramiko

    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with paramiko.Transport(sock) as transport:
                transport.start_client(timeout=8)
                return transport.get_remote_server_key()
    except (OSError, EOFError, paramiko.SSHException) as exc:
        raise HostIdentityError(f'Не удалось получить ключ SSH для {host}:{port}. Проверьте адрес и порт.') from exc


def verify_install_host(host, port, fingerprint):
    """Resolve first contact before the installer gets credentials or a job."""
    address = host_key_name(host, port)
    with trusted_ssh_client(host, port) as client:
        known = client.get_host_keys().lookup(address)
        if known:
            if fingerprint and not any(key.fingerprint == fingerprint for key in known.values()):
                raise HostIdentityError(f'Подтверждённый отпечаток не совпадает с сохранённым ключом {address}')
            return

    key = _read_server_key(host, port)
    if not fingerprint:
        raise ConfirmHostKey(address, key)
    if key.fingerprint != fingerprint:
        raise HostIdentityError(f'Во время подтверждения изменился ключ SSH для {address}')

    pin = _pin_path(address)
    pin.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=pin.parent, delete=False) as tmp:
        temporary = Path(tmp.name)
        tmp.write(f'{address} {key.get_name()} {key.get_base64()}\n'.encode('ascii'))
    try:
        os.link(temporary, pin)
    except FileExistsError:
        if pin.read_bytes() != temporary.read_bytes():
            raise HostIdentityError(f'Для {address} уже подтверждён другой ключ SSH')
    finally:
        temporary.unlink()


def _connect_host(host: str, user: str, port: int, *, password: str = '', key_path: str = '', timeout: int = 20):
    import paramiko

    if not host:
        raise RuntimeError('нет адреса сервера')
    client = trusted_ssh_client(host, int(port or 22))
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
    try:
        client.connect(**kwargs)
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise HostIdentityError(f'Для {host} изменился SSH-ключ хоста') from exc
    except Exception:
        client.close()
        raise
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
