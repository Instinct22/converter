#!/usr/bin/env python3
"""Поднять или переразвернуть Grafana на отдельном сервере.

Адрес, пароль SSH, пароль входа в Grafana и токен записи метрик
берутся из scripts/grafana.env. Этого файла в git нет.
Пустые GRAFANA_ADMIN_PASSWORD и GRAFANA_WRITE_TOKEN скрипт
генерирует сам и дописывает в тот же файл.

Пример:
  py -3 scripts/deploy_grafana.py

Повторный запуск не стирает историю метрик. Первый запуск дольше:
он ставит Docker и скачивает образы. Дальше хватает секунд.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.grafana_host import (  # noqa: E402
    GrafanaHost,
    load_env_file,
    new_admin_password,
    new_write_token,
    parse_markers,
    redact,
    remote_script,
    update_env_file,
)
from app.settings import settings  # noqa: E402
from app.ssh_access import run_remote  # noqa: E402

ENV_FILE = Path(__file__).with_name('grafana.env')


def _failure_text(shown: str, markers: dict[str, str], code: int) -> str:
    noise = ('Extracting', 'Pulling', 'Pull complete', 'Download', 'Waiting', 'Layer')
    lines = []
    for raw in (shown or '').splitlines():
        line = raw.strip()
        if not line or any(token in line for token in noise):
            continue
        lines.append(line)
    head = markers.get('GRAFANA_ERROR') or f'установщик завершился с кодом {code}'
    tail = '\n'.join(lines[-40:])
    if tail and tail != head:
        return head + '\n' + tail
    return head or 'установщик не дошёл до GRAFANA_READY'


def main() -> None:
    load_env_file(ENV_FILE)
    host = os.environ.get('GRAFANA_SSH_HOST', '').strip()
    user = (os.environ.get('GRAFANA_SSH_USER', '').strip() or 'root')
    password = os.environ.get('GRAFANA_SSH_PASSWORD', '').strip()
    if not host or not password:
        raise SystemExit(
            'Заполните scripts/grafana.env: GRAFANA_SSH_HOST и GRAFANA_SSH_PASSWORD. '
            'Образец — scripts/grafana.env.example.'
        )
    try:
        port = int(os.environ.get('GRAFANA_SSH_PORT', '').strip() or '22')
    except ValueError as exc:
        raise SystemExit('GRAFANA_SSH_PORT должен быть числом') from exc
    admin_user = (os.environ.get('GRAFANA_ADMIN_USER', '').strip() or 'admin')
    admin_password = os.environ.get('GRAFANA_ADMIN_PASSWORD', '').strip()
    write_token = os.environ.get('GRAFANA_WRITE_TOKEN', '').strip()
    generated: dict[str, str] = {}
    if not admin_password:
        admin_password = new_admin_password()
        generated['GRAFANA_ADMIN_PASSWORD'] = admin_password
    if not write_token:
        write_token = new_write_token()
        generated['GRAFANA_WRITE_TOKEN'] = write_token
    if generated:
        update_env_file(ENV_FILE, generated)
        print('Недостающие секреты Grafana дописаны в scripts/grafana.env.')
    spec = GrafanaHost(
        host=host,
        domain=os.environ.get('GRAFANA_DOMAIN', '').strip(),
        admin_user=admin_user,
        admin_password=admin_password,
        write_token=write_token,
        ssh_port=port,
        master_ip=(settings.master_ip or '').strip(),
        acme_email=(os.environ.get('GRAFANA_ACME_EMAIL', '').strip() or 'admin@aegis-gate.ru'),
    )
    hidden = [admin_password, write_token, password]
    script = remote_script(spec)
    print(f'Подключаюсь к {host}. Первый запуск качает образы, повторный занимает секунды.')
    try:
        code, out, err = run_remote(
            host,
            user,
            port,
            script,
            password=password,
            timeout=900,
        )
    except Exception as exc:
        raise SystemExit(redact(f'Не удалось зайти по SSH: {exc}', hidden)) from exc
    shown = redact((out or '') + '\n' + (err or ''), hidden)
    markers = parse_markers(shown)
    if code != 0 or markers.get('GRAFANA_ERROR') or markers.get('GRAFANA_READY') != '1':
        raise SystemExit(_failure_text(shown, markers, code))
    print(f"Grafana: {markers.get('GRAFANA_URL')}")
    print(f"Логин: {markers.get('GRAFANA_USER')}")
    print('Пароль администратора — GRAFANA_ADMIN_PASSWORD в scripts/grafana.env.')
    print(f"Приём метрик: {markers.get('GRAFANA_WRITE')}")
    print('Токен — GRAFANA_WRITE_TOKEN в том же файле, заголовок Authorization: Bearer.')
    if spec.domain:
        print('Сертификат Let\'s Encrypt на домен, Caddy продлевает сам.')
    else:
        print('Сертификат Let\'s Encrypt на IP. Он живёт около шести дней, Caddy продлевает сам.')


if __name__ == '__main__':
    try:
        main()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
