# NOTES — карта проекта XUI Master

> Быстрый ориентир, чтобы не перечитывать весь проект. Актуально на 2026-11-15.

## Что это
**XUI Master** — веб-панель (FastAPI + SQLModel/SQLite) для управления парком серверов
с 3x-ui (VLESS/Reality-прокси): ноды, клиенты, подписки Mihomo/Clash, защита (fail2ban/файрвол),
проверка доступности из РФ, индикатор доступных обновлений панелей/ядер (сами обновления — вручную на ноде).

## Стек / запуск / тесты
- Python, FastAPI 0.115, SQLModel 0.0.22, httpx, APScheduler, paramiko (SSH), jinja2.
- Запуск: `python -m app` (или `uvicorn app.main:app`). Хост/порт в `.env` (`host=0.0.0.0`, `port=8080`).
- Тесты: `.\.venv\Scripts\python.exe -m pytest -q` (из корня). Один предсуществующий сбой
  `tests/test_render_client.py::test_render_injects_node_proxy` (mihomo-шаблон про auth.gitlab.com) —
  падает и на чистом HEAD, не наш.
- Миграции БД: **автоматом** в `init_db()` (lifespan) — ALTER/CREATE, без alembic.
- БД: `data/master.db`. Секрет сессии: `data/session_secret`.

## Точка входа
`app/main.py` — lifespan: `init_db()` → `seed_if_empty` → `ensure_default_node_templates` →
`init_sub_path` → динамические роуты подписки → `start_scheduler()`.
Middleware: SessionMiddleware (cookie `master_session`). Static `/static`.

## Роутеры (app/routers/)
- `api.py` — prefix `/api`, `Depends(require_admin)`. Основной REST: ноды, клиенты, шаблоны,
  reachability, защита, overview.
- `ui.py` — HTML-страницы (Jinja): `/` (dashboard), `/nodes`, `/nodes/{id}`, `/clients`,
  `/templates`, `/protection`, `/releases`, `/config`, `/login`.
- `sub.py` — выдача подписок: `/mihomo/{token}`, `/clash/{token}`, `/sub/{token}` + секретные пути.
- `updates.py` — **не про ноды!** Это автообновление самого приложения AegisGate:
  `/api/app/latest`, `/api/app/download/{filename}`.

## Модули app/ (по назначению)
- `models.py` — SQLModel-таблицы (см. ниже).
- `database.py` — движок, `init_db()` + словарь `_NODE_ADD_COLUMNS` для ALTER.
- `xui.py` — `XuiClient` (httpx, **verify=False**, Bearer-токен, без /login). Все вызовы панели.
- `overview.py` — `probe_nodes`/`probe_node` (онлайн/CPU/RAM/версии), `store_versions`.
- `reachability.py` — TCP-пробы портов из РФ (`probe_nodes_rf`), «доходит ли до клиентов».
- `node_updates.py` — **read-only** снятие latest-версий панели/ядра (только индикатор; см. ниже).
- `provision.py` — раскладка клиентов по нодам/входам, `disable_expired`, шаблоны по умолчанию.
- `mihomo.py` — рендер YAML-подписки Mihomo. `sub_link.py` — токены/пути подписок.
- `xui_install.py` — первичная установка 3x-ui по SSH (paramiko) + файрвол.
- `firewall.py`, `fail2ban.py` — защита нод. `neighbor_scan.py`, `reality_scan.py`, `tls_sni.py`,
  `crypto_reality.py`, `parse_inbound.py`, `flags.py`, `util.py` — вспомогательное.
- `scheduler.py` — APScheduler, **интервал 10 мин**: `disable_expired` → `probe_nodes` →
  `store_versions` → **read-only `check_updates`** (только latest для лампочки) → `_refresh_rf`.
  **Автообновления нод НЕТ** (cron удалён намеренно).
- `settings.py` — pydantic-settings, `.env`. `bootstrap.py` — сид при пустой БД.

## Модели (models.py)
`Node` (panel_url, api_token, ssh_*, rf_ok, firewall_on, xui_version/xray_version,
**panel_latest_version/xray_latest_version**, install_state, enabled, sort_order),
`InboundTemplate`, `NodeTemplateAssignment`, `NodeInbound`, `Client` (slug, uuid, sub_token, expire),
`ClientPlacement`, `ConfigDoc` (yaml_text, pool_group_names, global_extra_snis), `AppSetting`.

## Обновление версий на нодах — только индикатор (обновление делаем вручную на ноде)
Панель сама знает latest (`getPanelUpdateInfo` → GitHub MHSanaei/3x-ui; `getXrayVersion` →
XTLS/Xray-core). Планировщик read-only снимает latest в `panel_latest_version`/`xray_latest_version`.
Против версий в таблице нод рисуется индикатор: **жёлтая стрелка ↑** (есть версия новее) либо
**зелёный текст версии** (совпадает с последней — всё ок). Вызова обновления из мастера НЕТ.
- `node_updates.py`: только `check_updates` (read-only latest → в Node). `perform_update`/авто-откат/пул — УДАЛЕНЫ.
- `xui.py`: read-only `get_panel_update_info`, `get_xray_versions`. `update_panel`/`get_update_status`/`install_xray` — УДАЛЕНЫ.
- API: update-эндпоинтов нод НЕТ (удалены `POST /api/nodes/update`, `POST /api/nodes/updates/dismiss`, `GET /api/nodes/updates`).
- UI: в таблице нод ячейки версии с индикатором (`app.js: applyNodeVersions` + inline в `dashboard.html`).
  Модалка `_update_nodes.html`, кнопка «Обновления», `initUpdateControls`, `UpdateNotification` — УДАЛЕНЫ.
- Тесты: `tests/test_node_updates.py` — 3 шт (только `check_updates`).

## Тестовые моки нод
`scripts/mock_panels.py` — фейковые панели 3x-ui на портах 20801–20804 (DE-1/NL-2/US-3/FI-4),
разные версии. `python scripts/mock_panels.py --seed` (сид БД) / `--serve` (HTTP).
Версии latest в моках условные (3.11 / 25.11.7) — в бою берутся с реальной панели.
Debug-скрипты `scripts/_inspect_db.py`, `scripts/_probe_updates.py` — untracked, временные.

## Конвенции / грабли
- **Кэш-буст**: `app.css?v=NN` и `app.js?v=NN` в `app/templates/base.html` — при правке статики
  поднимать номер, иначе браузер держит старый файл.
- Общие partials: `_node_controls.html`, `_client_controls.html` (include в dashboard/nodes).
- Общий JS в `app/static/app.js`, экспорт `window.XUI = {...}`; инлайн-скрипты в шаблонах.
- `XuiClient`: `verify=False`, Bearer-токен обязателен, `unreachable`-флаг (новый клиент на каждый пинг).
- Комментарии и UI-тексты — на русском.
