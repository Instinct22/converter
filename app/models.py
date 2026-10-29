from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel

from app.flags import flagcdn, to_emoji, to_iso


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
        return flagcdn(self.flag)


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
