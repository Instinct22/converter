# NOTES — карта проекта XUI Master

> Быстрый ориентир, чтобы не перечитывать весь проект. Актуально на 2026-11-15.

## Что это
**XUI Master** — веб-панель (FastAPI + SQLModel/SQLite) для управления парком серверов
с 3x-ui (VLESS/Reality-прокси): ноды, клиенты, подписки Mihomo/Clash, защита (fail2ban/файрвол),
проверка доступности из РФ, обновление версий панелей/ядер на нодах прямо из мастера через API панели
(кликабельная стрелка ↑ + подтверждение; авто-откат ядра при сбое).

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
- `node_updates.py` — снятие latest-версий (read-only) + запуск обновления панели/ядра через API и откат ядра (см. ниже).
- `provision.py` — раскладка клиентов по нодам/входам, `disable_expired`, шаблоны по умолчанию.
- `mihomo.py` — рендер YAML-подписки Mihomo. `sub_link.py` — токены/пути подписок.
- `xui_install.py` — первичная установка 3x-ui по SSH (paramiko) + файрвол.
- `firewall.py`, `fail2ban.py` — защита нод. `neighbor_scan.py`, `reality_scan.py`, `tls_sni.py`,
  `crypto_reality.py`, `parse_inbound.py`, `flags.py`, `util.py` — вспомогательное.
- `scheduler.py` — APScheduler, **интервал 10 мин**: `disable_expired` → `probe_nodes` →
  `store_versions` → **read-only `check_updates`** (только latest для индикатора) → `_refresh_rf`.
  Планировщик **сам ничего не обновляет** — обновление панели/ядра запускается только по клику в UI.
- `settings.py` — pydantic-settings, `.env`. `bootstrap.py` — сид при пустой БД.

## Модели (models.py)
`Node` (panel_url, api_token, ssh_*, rf_ok, firewall_on, xui_version/xray_version,
**panel_latest_version/xray_latest_version**, **update_state/update_kind/update_prev_version/update_target_version**,
install_state, enabled, sort_order),
`InboundTemplate`, `NodeTemplateAssignment`, `NodeInbound`, `Client` (slug, uuid, sub_token, expire),
`ClientPlacement`, `ConfigDoc` (yaml_text, pool_group_names, global_extra_snis), `AppSetting`.

## Обновление версий панели/ядра на нодах (из мастера, через API панели)
Панель сама знает latest (`getPanelUpdateInfo` → GitHub MHSanaei/3x-ui; `getXrayVersion` →
XTLS/Xray-core). Планировщик read-only снимает latest в `panel_latest_version`/`xray_latest_version`.
Против версий в таблице нод — индикатор: **жёлтая ↑ (кликабельная)** = есть версия новее;
**зелёный текст версии** = совпадает с последней (всё ок). Клик по ↑ → окно подтверждения
«обновить с X на Y» → установка через API панели.
- `node_updates.py`: `check_updates` (read-only latest → в Node) + `start_update` (запуск
  обновления через API панели, ставит `running`) + `reconcile_update` (разрешает статус по
  ФАКТИЧЕСКОЙ версии: версия дошла до целевой/новее → успех (зелёный); offline по таймауту →
  `failed`; failed при возврате online → сброс в ↑). Откат УДАЛЁН (панель 3x-ui не понижает по
  API, переустановка прежней версии ядра падает — механизм не работал).
- `xui.py`: read-only `get_panel_update_info`, `get_xray_versions` + `update_panel`, `install_xray`.
- API: `POST /api/nodes/{id}/update` (kind=panel|xray). Состояние — в колонках
  `update_state`(running/failed)/`update_kind`/`update_target_version`/`update_started_at`.
  Эндпоинт `/update/rollback` и колонка `update_prev_version` — УДАЛЕНЫ.
- UI: ячейки версии с индикатором + confirm-окно и запуск (`app.js: applyNodeVersions`/`renderVerIcon`
  + inline в `dashboard.html`). Красный «!» при сбое — НЕкликабелен («проверьте ноду вручную»).
  Старые модалка `_update_nodes.html`, кнопка «Обновления», `initUpdateControls`, `UpdateNotification` — УДАЛЕНЫ.
- Успех определяется по фактической версии ноды (обзор/планировщик каждый цикл снимают версии):
  ложного «сбоя» после успешного обновления больше нет.
- Тесты: `tests/test_node_updates.py` — 15 шт (check_updates, запуск panel/xray, отказ панели,
  reconcile_update: успех/новее/ожидание/таймаут/сброс failed).

## Тестовые моки нод
`scripts/mock_panels.py` — фейковые панели 3x-ui на портах 20801–20804 (DE-1/NL-2/US-3/FI-4),
разные версии. `python scripts/mock_panels.py --seed` (сид БД) / `--serve` (HTTP).
Мок принимает `updatePanel`/`installXray` и реально меняет версию — видно полный цикл обновления.
Версии latest в моках условные (3.11 / 25.11.7) — в бою берутся с реальной панели.

## Конвенции / грабли
- **Кэш-буст**: `app.css?v=NN` и `app.js?v=NN` в `app/templates/base.html` — при правке статики
  поднимать номер, иначе браузер держит старый файл.
- Общие partials: `_node_controls.html`, `_client_controls.html` (include в dashboard/nodes).
- Общий JS в `app/static/app.js`, экспорт `window.XUI = {...}`; инлайн-скрипты в шаблонах.
- `XuiClient`: `verify=False`, Bearer-токен обязателен, `unreachable`-флаг (новый клиент на каждый пинг).
- Комментарии и UI-тексты — на русском.
