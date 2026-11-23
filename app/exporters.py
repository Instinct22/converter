"""node_exporter на каждой машине и доставка метрик в VictoriaMetrics.

Экспортёр слушает только 127.0.0.1:9100. vmagent на той же машине
читает его и сам отправляет ряды на Grafana. Входящий порт для метрик
не открывается: файрвол Master такой порт либо закроет, либо выставит
в интернет.
"""
from __future__ import annotations

import json
import re
import shlex
import threading

from sqlalchemy import update
from sqlmodel import Session, select

from app.models import AppSetting, Node

NODE_EXPORTER_VERSION = '1.13.1'
VMAGENT_VERSION = '1.156.0'
_URL_KEY = 'grafana_write_url'
_TOKEN_KEY = 'grafana_write_token'
_SHA = {
    'amd64': '5c00c5234f1ee45900b25539a5a0ab82146a098c15c16a4ec3bc855b597a6477',
    'arm64': '96d82b3b261803f89815b325601cbbc58f49cd8265617bfde1527211934bdd48',
}


def remember_grafana_target(session: Session, url: str, token: str) -> None:
    _put(session, _URL_KEY, (url or '').strip())
    _put(session, _TOKEN_KEY, (token or '').strip())
    session.commit()


def grafana_target(session: Session) -> tuple[str, str]:
    url = _get(session, _URL_KEY)
    token = _get(session, _TOKEN_KEY)
    if url and token:
        return url, token
    node = session.exec(
        select(Node).where(Node.install_kind == 'grafana').where(Node.install_state == 'done')
    ).first()
    if node is None:
        raise ValueError('Сначала должна стоять Grafana')
    found = _target_from_log(node)
    if found is None:
        raise ValueError('У Grafana нет адреса или токена записи')
    remember_grafana_target(session, found[0], found[1])
    return found


def exporter_script(*, host: str, name: str, write_url: str, token: str) -> str:
    if not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]+)?/api/v1/write', write_url):
        raise ValueError('Некорректный HTTPS-адрес VictoriaMetrics')
    label = json.dumps((name or host)[:80], ensure_ascii=True)
    address = json.dumps(host, ensure_ascii=True)
    return f'''set -eu
export PATH="/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
exec 9>/run/master-exporters.lock
flock -w 600 9
arch=$(uname -m)
case "$arch" in
  x86_64) goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  *)
    echo "EXPORTER_ERROR=архитектура $arch не поддерживается"
    exit 2
    ;;
esac
echo "Ставлю node_exporter {NODE_EXPORTER_VERSION}"
tmp=$(mktemp -d)
curl -fsSL -o "$tmp/node.tgz" "https://github.com/prometheus/node_exporter/releases/download/v{NODE_EXPORTER_VERSION}/node_exporter-{NODE_EXPORTER_VERSION}.linux-$goarch.tar.gz"
echo "{_SHA['amd64']}  $tmp/node.tgz" > "$tmp/node.sha"
if [ "$goarch" = "arm64" ]; then
  echo "{_SHA['arm64']}  $tmp/node.tgz" > "$tmp/node.sha"
fi
sha256sum -c "$tmp/node.sha"
tar -C "$tmp" -xzf "$tmp/node.tgz"
install -m 755 "$tmp/node_exporter-{NODE_EXPORTER_VERSION}.linux-$goarch/node_exporter" /usr/local/bin/node_exporter
rm -rf "$tmp"
cat > /etc/systemd/system/node_exporter.service <<'EOF'
[Unit]
Description=node_exporter
After=network-online.target
[Service]
ExecStart=/usr/local/bin/node_exporter --web.listen-address=127.0.0.1:9100
Restart=always
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
echo "Ставлю vmagent {VMAGENT_VERSION}"
tmp=$(mktemp -d)
curl -fsSL -o "$tmp/vm.tgz" "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v{VMAGENT_VERSION}/vmutils-linux-$goarch-v{VMAGENT_VERSION}.tar.gz"
tar -C "$tmp" -xzf "$tmp/vm.tgz"
install -m 755 "$tmp/vmagent-prod" /usr/local/bin/vmagent-prod
rm -rf "$tmp"
install -d -m 755 /etc/vmagent /var/lib/vmagent
umask 077
printf '%s' {shlex.quote(token)} > /etc/vmagent/token
chmod 600 /etc/vmagent/token
cat > /etc/vmagent/scrape.yml <<'EOF'
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: node
    static_configs:
      - targets: ["127.0.0.1:9100"]
        labels:
          node: {label}
          host: {address}
          instance: {address}
EOF
cat > /etc/systemd/system/vmagent.service <<'EOF'
[Unit]
Description=vmagent
After=network-online.target node_exporter.service
[Service]
ExecStart=/usr/local/bin/vmagent-prod -httpListenAddr=127.0.0.1:8429 -promscrape.config=/etc/vmagent/scrape.yml -remoteWrite.url={write_url} -remoteWrite.bearerTokenFile=/etc/vmagent/token -remoteWrite.forcePromProto=true -remoteWrite.maxDiskUsagePerURL=256MB -remoteWrite.tmpDataPath=/var/lib/vmagent
Restart=always
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable node_exporter vmagent >/dev/null
systemctl restart node_exporter
systemctl restart vmagent
sleep 2
if ! curl -fsS http://127.0.0.1:9100/metrics | grep -q '^node_'; then
  echo "EXPORTER_ERROR=node_exporter не отдал метрики"
  exit 1
fi
if ! systemctl is-active --quiet vmagent; then
  echo "EXPORTER_ERROR=vmagent не запустился"
  systemctl status vmagent --no-pager || true
  exit 1
fi
echo "Проверяю доставку в VictoriaMetrics"
for attempt in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8429/metrics | awk '/^vmagent_remotewrite_bytes_sent_total[{{ ]/ && $NF+0 > 0 {{ok=1}} END {{exit !ok}}'; then
    echo EXPORTER_READY=1
    exit 0
  fi
  sleep 2
done
echo "EXPORTER_ERROR=VictoriaMetrics не подтвердила приём за минуту"
exit 1
'''


def apply_exporter(session: Session, node_id: int, runner=None) -> str:
    node = session.get(Node, node_id)
    if node is None:
        return ''
    if (node.install_state or '') == 'installing':
        _remember(session, node, 'failed', 'сначала должна закончиться установка')
        return f'{node.name}: экспортёр подождёт окончания установки'
    from app.ssh_access import can_ssh

    if runner is None and not can_ssh(node):
        _remember(session, node, 'failed', 'нет входа SSH')
        return f'{node.name}: нет входа SSH'
    try:
        url, token = grafana_target(session)
    except ValueError as exc:
        _remember(session, node, 'failed', str(exc))
        return f'{node.name}: {exc}'
    _remember(session, node, 'installing', 'ставлю node_exporter')
    try:
        from app.ssh_access import _target
        host, user, port = _target(node)
        script = exporter_script(
            host=host, name=node.name or '', write_url=url, token=token,
        )
        if node.is_grafana():
            from app.grafana_host import dashboard_script
            from urllib.parse import urlsplit
            script = 'set -eu\n' + dashboard_script(urlsplit(node.panel_url).hostname) + script
        if runner is None:
            from app.xui_install import run_ssh
            from app.ssh_access import AUTH_BOTH, AUTH_KEY, PRIVATE_PATH, resolved_auth

            user = (node.ssh_user or 'root').strip() or 'root'
            use_key = resolved_auth(node) in {AUTH_KEY, AUTH_BOTH} and not (node.ssh_password or '').strip()

            def _progress(line: str) -> None:
                text = (line or '').strip()
                if not text or text.startswith('EXPORTER_'):
                    return
                _remember(session, node, 'installing', text)

            code, output = run_ssh(
                host,
                user,
                script,
                str(PRIVATE_PATH) if use_key else '',
                node.ssh_password,
                port=port,
                prefer_key=use_key,
                on_line=_progress,
            )
        else:
            code, output = runner(node.public_host, script)
    except Exception as exc:
        _remember(session, node, 'failed', str(exc)[:240])
        return f'{node.name}: {exc}'
    if code != 0 or 'EXPORTER_READY=1' not in (output or ''):
        message = ''
        for line in (output or '').splitlines():
            if line.startswith('EXPORTER_ERROR='):
                message = line.split('=', 1)[1].strip()
        message = message or f'код {code}'
        _remember(session, node, 'failed', message[:240])
        return f'{node.name}: {message}'
    _remember(session, node, 'done', 'метрики уходят на Grafana')
    return f'{node.name}: метрики уходят на Grafana'


def start_exporters(session: Session, node_id: int | None = None) -> int:
    grafana_target(session)
    query = update(Node).where(Node.install_state != 'installing', Node.exporter_state != 'installing')
    if node_id is not None:
        query = query.where(Node.id == node_id)
    ids = session.execute(query.values(exporter_state='installing', exporter_note='в очереди')
                          .returning(Node.id)).scalars().all()
    session.commit()
    if not ids:
        raise ValueError('Установка уже выполняется или сервер ещё не готов')

    def _run() -> None:
        for target_id in ids:
            with Session(session_bind) as local:
                try:
                    apply_exporter(local, target_id)
                except Exception as exc:
                    local.rollback()
                    node = local.get(Node, target_id)
                    if node:
                        _remember(local, node, 'failed', f'Ошибка установки ({type(exc).__name__})')

    session_bind = session.get_bind()
    try:
        threading.Thread(target=_run, name='exporters', daemon=True).start()
    except RuntimeError:
        session.execute(update(Node).where(Node.id.in_(ids)).values(
            exporter_state='failed', exporter_note='Master не смог запустить установку'))
        session.commit()
        raise
    return len(ids)


def _target_from_log(node: Node) -> tuple[str, str] | None:
    url = (node.panel_url or '').strip().rstrip('/')
    token = ''
    for line in (node.install_log or '').splitlines():
        if line.startswith('Токен записи:'):
            token = line.split(':', 1)[1].strip()
    if not url.startswith('http') or not token:
        return None
    return url + '/api/v1/write', token


def _put(session: Session, key: str, value: str) -> None:
    row = session.get(AppSetting, key)
    if row is None:
        session.add(AppSetting(key=key, value=value))
    else:
        row.value = value
        session.add(row)


def _get(session: Session, key: str) -> str:
    row = session.get(AppSetting, key)
    return (row.value or '').strip() if row is not None else ''


def _remember(session: Session, node: Node, state: str, note: str) -> None:
    from app.activity import worker_state
    worker_state(session, node, 'agent', 'Установка агента метрик',
                 {'installing': 'running', 'done': 'ok', 'failed': 'error'}[state], note)
    node.exporter_state = state
    node.exporter_note = (note or '')[:240]
    session.add(node)
    session.commit()
