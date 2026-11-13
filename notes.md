# NOTES — карта проекта XUI Master

> Быстрый ориентир, чтобы не перечитывать весь проект. Актуально на 2026-11-13.

## Что это
**XUI Master** — веб-панель (FastAPI + SQLModel/SQLite) для управления парком серверов
с 3x-ui (VLESS/Reality-прокси): ноды, клиенты, подписки Mihomo/Clash, защита (fail2ban/файрвол),
проверка доступности из РФ, авто- и ручные обновления панелей/ядер.

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
  reachability, защита, overview, обновления.
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
- `node_updates.py` — **ручное** обновление нод (см. статус ниже).
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
**panel_latest_version/xray_latest_version**, update_state, install_state, enabled, sort_order),
`InboundTemplate`, `NodeTemplateAssignment`, `NodeInbound`, `Client` (slug, uuid, sub_token, expire),
`ClientPlacement`, `ConfigDoc` (yaml_text, pool_group_names, global_extra_snis),
`AppSetting`, `UpdateNotification` (node_name?, message, dismissed).

## ✅ ЗАДАЧА: обновление нод — ВЫПОЛНЕНО (ветка feature/node-updates, коммит c70b630)
Только **ручное** обновление через API панели (без SSH). Панель сама знает latest
(`getPanelUpdateInfo` → GitHub MHSanaei/3x-ui; `getXrayVersion` → XTLS/Xray-core).
- `node_updates.py`: `check_updates` (read-only latest), `perform_update` (панель→ядро→ожидание
  возврата→проверка ядра; **авто-откат** ядра, если новое не поднялось; `_reserve_nodes` — пул
  «живые+rf_ok ≥2» перед шагом ядра; `skip_floor` — в обход пула). `auto_update_run` УДАЛЁН.
- `xui.py`: `get_panel_update_info`, `update_panel`, `get_update_status`, `get_xray_versions`, `install_xray`.
- API: `GET /api/nodes/updates?refresh=`, `POST /api/nodes/update {node_ids, skip_floor}`,
  `POST /api/nodes/updates/dismiss`.
- UI: кнопка «Обновления» + модалка `_update_nodes.html` (клики по строке, кнопка тёмная если
  ничего не выбрано, чекбокс «Игнорировать защиту недоступности»). Все результаты — в жёлтый
  блок «Уведомления» (`UpdateNotification`). В таблице нод: жёлтая пульс-лампочка `has-update`
  если latest≠current, зелёный `is-current` если равно.
- Тесты: `tests/test_node_updates.py` — 12 шт (включая откат).

## Тестовые моки нод
`scripts/mock_panels.py` — фейковые панели 3x-ui на портах 20801–20804 (DE-1/NL-2/US-3/FI-4),
разные версии. `python scripts/mock_panels.py --seed` (сид БД) / `--serve` (HTTP).
Версии latest в моках условные (3.11 / 25.11.7) — в бою берутся с реальной панели.
Debug-скрипты `scripts/_inspect_db.py`, `scripts/_probe_updates.py` — untracked, временные.

## Конвенции / грабли
- **Кэш-буст**: `app.css?v=NN` и `app.js?v=NN` в `app/templates/base.html` — при правке статики
  поднимать номер, иначе браузер держит старый файл.
- Общие partials: `_node_controls.html`, `_client_controls.html`, `_update_nodes.html` (include в dashboard/nodes).
- Общий JS в `app/static/app.js`, экспорт `window.XUI = {...}`; инлайн-скрипты в шаблонах.
- `XuiClient`: `verify=False`, Bearer-токен обязателен, `unreachable`-флаг (новый клиент на каждый пинг).
- Комментарии и UI-тексты — на русском.
