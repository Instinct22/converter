# XUI Master

Мастер-нода над панелями **3x-ui**: клиенты, срок подписки, inbound на нодах, единый Mihomo YAML.

Клиенту выдаётся одна ссылка:

`https://<ваш-хост>/clash/<token>`

в формате подписки Clash Meta / DHQClash (полный профиль, не сырой список с панели).

## Что умеет

- UI: ноды, клиенты, шаблоны inbound, редактор конфига
- Добавление / удаление / отключение нод в пуле
- Создание VLESS+REALITY inbound на ноде по шаблону (ключи генерируются сами)
- Sync существующих inbound с 3x-ui
- Создание клиента сразу на всех включённых inbound всех нод (один UUID)
- Удаление и продление срока; просроченные отключаются каждые 10 минут
- Сборка YAML: прокси, extra SNI, `route-exclude-address` и `IP-CIDR … DIRECT` по IP нод

## Запуск

```powershell
cd e:\GitHub\converter
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
# задайте ADMIN_USERNAME, ADMIN_PASSWORD, PUBLIC_BASE_URL
python -m app
```

Откройте `http://127.0.0.1:8080` — браузер спросит логин и пароль из `.env`.

Docker (локально):

```powershell
copy .env.example .env
docker compose up --build -d
```

## GitHub → Docker Hub → VPS

Push в `main` запускает тесты на Python 3.12, публикует образ и разворачивает тег `sha-<commit>` на `5.180.174.204` (`/opt/converter`). Снаружи открыты 80 и 443: Caddy выпускает сертификаты и отдаёт сайт, панель и API обновлений. Панель на `127.0.0.1:8080` остаётся только для самого сервера.

Secrets (Settings → Secrets and variables → Actions):

- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`
- `DEPLOY_SSH_PASSWORD` — root по SSH на VPS
- `ADMIN_USERNAME` (логин панели, обычно `admin`) / `ADMIN_PASSWORD` (пароль входа)

Variables: `PUBLIC_BASE_URL` (по умолчанию `https://master.aegis-gate.ru`) и `UPDATE_BASE_URL` (по умолчанию `https://api.aegis-gate.ru`).

На голом Debian 13 pipeline сам ставит `ca-certificates`, `curl`, `gnupg`, `iptables`, `nftables`, `uidmap`, `dbus`, `kmod`, `iproute2`, затем Docker CE и compose plugin.

### Проверка перед заменой контейнеров

CI запускает `python -m app.preflight` в новом образе до `docker compose up`. Проверка прогоняет миграции на временной копии SQLite, читает список входов включённых панелей и проверяет наличие доверенных ключей для управляемых SSH-нод. При ошибке текущий контейнер продолжает работать. Повторите выкладку после устранения причины.

Для SSH добавьте публичный **ключ хоста VPS** в `data/ssh/known_hosts` в формате OpenSSH. Сверьте отпечаток через консоль провайдера. Для порта, отличного от 22, используйте запись `[host]:port`. Для панели с собственным центром сертификации положите его публичный сертификат PEM в `data/panel-ca.pem`. Адрес панели должен совпадать с именем или IP в сертификате. HTTP поддерживается через локальный туннель.

После установки пароль выдаётся один раз кнопкой в карточке сервера. Административный API использует `POST /api/nodes/{id}/install-credentials`. При частичном отзыве `DELETE /api/clients/{id}` возвращает `ok: false` и журнал по нодам. Подписка сразу отключается, повторный DELETE завершает отзыв после восстановления связи. Для изменения назначений через API передавайте `template_ids` явно, включая `[]` при снятии всех назначений.

## Типовой порядок

1. Проверьте inbound-шаблоны (gRPC 443 и xhttp 8443 уже есть — поправьте dest/SNI под свои).
2. **Ноды** → URL панели (`https://ip:2053/webBasePath/`), логин, **public host** (IP, куда ходит клиент).
3. Можно сразу выбрать шаблоны — мастер создаст inbound и затем sync.
4. Либо **Sync inbound**, если входящие уже есть, отметьте «в подписке», при необходимости extra SNI.
5. В **Конфиг Mihomo** вставьте свой профиль (из `test11`) **сохранив маркеры** `XUI_PROXIES`, `XUI_POOL`, `XUI_TUN_EXCLUDE`, `XUI_CIDRS`.
6. **Клиенты** → создать → скопировать `/clash/<token>`.

Глобальные extra SNI (например `auth.gitlab.com,gprd.gitlab.com`) задаются в редакторе конфига и применяются к inbound с флагом **Global SNI**.

## Маркеры шаблона

Блоки между комментариями **перезаписываются** при каждой выдаче:

| Маркер | Содержимое |
|--------|------------|
| `XUI_PROXIES` | список `proxies` (VLESS Reality, все SNI) |
| `XUI_POOL` | имена прокси в группах (можно несколько раз) |
| `XUI_TUN_EXCLUDE` | IP нод `/32` для TUN |
| `XUI_CIDRS` | `IP-CIDR,…,DIRECT,no-resolve` в `rules` |

## API 3x-ui

Master передаёт API-токен панели в заголовке Authorization при обращении к 3x-ui.
Нужен доступ **с хоста Master → панель каждой ноды**. Подписку клиентам лучше отдавать с RU/доступного IP (`PUBLIC_BASE_URL`).

Пароли панелей хранятся в SQLite `data/master.db` — ограничьте доступ к файлу.
