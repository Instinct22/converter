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
# задайте ADMIN_PASSWORD, SESSION_SECRET, PUBLIC_BASE_URL
python -m app
```

Откройте `http://127.0.0.1:8080`, пароль из `.env`.

Docker (локально):

```powershell
copy .env.example .env
docker compose up --build -d
```

## GitHub → Docker Hub → VPS

Push в `main` собирает образ `liiiiiiiiis/converter:latest` и поднимает его на `5.180.174.204` (`/opt/converter`, порт 8080).

Secrets (Settings → Secrets and variables → Actions):

- `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`
- `DEPLOY_SSH_PASSWORD` — root по SSH на VPS
- `ADMIN_PASSWORD` / `SESSION_SECRET`

Variable: `PUBLIC_BASE_URL` (по умолчанию `http://5.180.174.204:8080`).

На голом Debian 13 pipeline сам ставит `ca-certificates`, `curl`, `gnupg`, `iptables`, `nftables`, `uidmap`, `dbus`, `kmod`, `iproute2`, затем Docker CE и compose plugin.

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

Мастер логинится в панель как обычный админ и вызывает `/panel/api/inbounds/*`.  
Нужен доступ **с хоста Master → панель каждой ноды**. Подписку клиентам лучше отдавать с RU/доступного IP (`PUBLIC_BASE_URL`).

Пароли панелей хранятся в SQLite `data/master.db` — ограничьте доступ к файлу.
