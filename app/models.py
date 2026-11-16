from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel

from app.flags import country_name, flag_src, normalize_flags, to_emoji, to_iso


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Node(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    flag: str = ''
    name: str
    clash_name: str = ''
    panel_url: str
    api_token: str = ''
    public_host: str = ''
    enabled: bool = True
    sort_order: int = 0
    last_sync_at: Optional[datetime] = None
    last_error: str = ''
    sub_port: int = 2096
    sub_path: str = ''
    sub_clash_path: str = ''
    sub_scheme: str = 'https'
    ssh_user: str = 'root'
    ssh_port: int = 22
    ssh_password: str = ''
    # key — только ключ флота; both — ключ есть, пароль ещё включён;
    # password — в базе ещё лежит пароль; none — входа нет.
    ssh_auth: str = ''
    firewall_on: bool = False
    firewall_note: str = ''
    fail2ban_state: str = ''
    fail2ban_banned: int = 0
    fail2ban_day: int = 0
    fail2ban_note: str = ''
    # Доступен ли сервер клиентам из России (TCP-пробы с мастера, он стоит в РФ)
    rf_ok: bool = False
    rf_note: str = ''
    rf_checked_at: Optional[datetime] = None
    # Версии на самой ноде: панель 3x-ui и ядро Xray (снимаются при опросе)
    xui_version: str = ''
    xray_version: str = ''
    version_checked_at: Optional[datetime] = None
    # Автообновление: какие версии доступны на ноде и чем закончился последний прогон.
    # latest снимаются с getPanelUpdateInfo/getXrayVersion; current — xui_version/xray_version.
    panel_latest_version: str = ''
    xray_latest_version: str = ''
    update_checked_at: Optional[datetime] = None
    # Ручное обновление панели/ядра по API (запуск из UI, фон-поток ждёт возврата ноды):
    # '' | running | failed; kind — что обновляем (panel/xray); prev — на что откатывать.
    update_state: str = ''
    update_kind: str = ''
    update_target_version: str = ''
    update_started_at: Optional[datetime] = None
    install_state: str = ''
    install_log: str = ''
    install_ssl: str = ''
    created_at: datetime = Field(default_factory=utcnow)

    def clash_prefix(self) -> str:
        label = (self.clash_name or self.name).strip()
        emoji = to_emoji(self.flag)
        if emoji and label:
            return f'{emoji} {label}'
        return emoji or label

    def flag_iso(self) -> str:
        return to_iso(self.flag)

    def flag_image(self) -> str:
        return flag_src(self.flag)

    def flag_title(self) -> str:
        return country_name(self.flag)


class InboundTemplate(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    port: int
    protocol: str = 'vless'
    listen: str = ''
    network: str = 'grpc'
    security: str = 'reality'
    dest: str = 'www.cloudflare.com:443'
    server_names: str = 'www.cloudflare.com,cloudflare.com'
    grpc_service_name: str = 'grpc'
    grpc_authority: str = ''
    grpc_multi_mode: bool = False
    xhttp_path: str = '/'
    xhttp_host: str = ''
    xhttp_mode: str = 'auto'
    ws_path: str = '/'
    ws_host: str = ''
    fingerprint: str = 'chrome'
    flow: str = ''
    spider_x: str = '/'
    short_ids: str = ''
    sniffing: bool = False
    tls_cert_file: str = ''
    tls_key_file: str = ''
    tls_alpn: str = 'h2,http/1.1'
    tls_server_name: str = ''
    reject_unknown_sni: bool = False
    extra_snis: str = ''
    use_global_sni: bool = True
    enabled: bool = True
    # Подписка Mihomo / Clash для этого порта
    use_in_sub: bool = True
    provider_label: str = ''
    flags: str = ''

    def flag_badges(self) -> list[tuple[str, str, str]]:
        badges: list[tuple[str, str, str]] = []
        for iso in normalize_flags(self.flags).split(','):
            if not iso:
                continue
            badges.append((iso, flag_src(iso), country_name(iso)))
        return badges


class NodeTemplateAssignment(SQLModel, table=True):
    node_id: int = Field(foreign_key='node.id', primary_key=True)
    template_id: int = Field(foreign_key='inboundtemplate.id', primary_key=True)


class NodeInbound(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    node_id: int = Field(foreign_key='node.id', index=True)
    xui_inbound_id: int
    remark: str = ''
    port: int = 0
    protocol: str = 'vless'
    network: str = 'grpc'
    public_key: str = ''
    short_id: str = ''
    fingerprint: str = 'chrome'
    dest: str = ''
    server_names: str = ''
    grpc_service_name: str = ''
    xhttp_path: str = ''
    flow: str = ''
    use_in_sub: bool = True
    extra_snis: str = ''
    use_global_sni: bool = True
    display_prefix: str = ''
    # Master-side SNI/subscription: не затирать server_names при sync с панелью
    snis_locked: bool = False
    # Имя в Mihomo для alt-порта (8443): по умолчанию «yahoo»
    provider_label: str = ''


class Client(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    slug: str = Field(index=True, unique=True)
    uuid: str
    sub_token: str = Field(index=True, unique=True)
    enable: bool = True
    expire_at: Optional[datetime] = None
    traffic_limit_bytes: int = 0
    limit_ip: int = 0
    note: str = ''
    created_at: datetime = Field(default_factory=utcnow)


class ClientPlacement(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    client_id: int = Field(foreign_key='client.id', index=True)
    node_id: int = Field(foreign_key='node.id', index=True)
    inbound_id: int = Field(foreign_key='nodeinbound.id', index=True)
    ok: bool = False
    message: str = ''
    updated_at: datetime = Field(default_factory=utcnow)


class ConfigDoc(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    yaml_text: str
    pool_group_names: str = 'Reality pool,Reality pool fallback'
    global_extra_snis: str = 'auth.gitlab.com,gprd.gitlab.com'
    updated_at: datetime = Field(default_factory=utcnow)


class AppSetting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str = ''


class ClientPingReport(SQLModel, table=True):
    """Последняя сводка одного клиента. Новая заменяет старую."""

    client_id: int = Field(foreign_key='client.id', primary_key=True)
    seen_at: datetime = Field(default_factory=utcnow)
    app_version: str = ''
    platform: str = ''
    exit_server: str = ''
    servers_json: str = '[]'


class NodePingHour(SQLModel, table=True):
    """Час наблюдений клиентов по одной ноде.

    samples_json — медианы успешных отчётов этого часа. Старше двух недель
    список сжимается до одной медианы, старше 90 дней строка удаляется.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    node_id: int = Field(foreign_key='node.id', index=True)
    hour: datetime = Field(index=True)
    reports: int = 0
    fails: int = 0
    samples_json: str = '[]'
    reasons_json: str = '{}'
    rolled: bool = False
