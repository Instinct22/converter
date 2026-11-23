from collections.abc import Generator

from sqlalchemy import event, inspect, text
from sqlmodel import Session, SQLModel, create_engine

from app.settings import settings

engine = create_engine(
    settings.database_url,
    echo=False,
    connect_args={'check_same_thread': False},
)


@event.listens_for(engine, 'connect')
def _sqlite_pragma(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute('PRAGMA foreign_keys=ON')
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA busy_timeout=8000')
    cursor.close()


NODE_COLUMNS = {
    'sub_port': 'INTEGER DEFAULT 2096',
    'sub_path': "TEXT DEFAULT ''",
    'sub_clash_path': "TEXT DEFAULT ''",
    'sub_scheme': "TEXT DEFAULT 'https'",
    'ssh_user': "TEXT DEFAULT 'root'",
    'ssh_port': 'INTEGER DEFAULT 22',
    'ssh_password': "TEXT DEFAULT ''",
    'ssh_auth': "TEXT DEFAULT ''",
    'firewall_on': 'INTEGER DEFAULT 0',
    'firewall_note': "TEXT DEFAULT ''",
    'fail2ban_state': "TEXT DEFAULT ''",
    'fail2ban_banned': 'INTEGER DEFAULT 0',
    'fail2ban_day': 'INTEGER DEFAULT 0',
    'fail2ban_note': "TEXT DEFAULT ''",
    'install_state': "TEXT DEFAULT ''",
    'install_log': "TEXT DEFAULT ''",
    'install_ssl': "TEXT DEFAULT ''",
    'install_kind': "TEXT DEFAULT ''",
    'exporter_state': "TEXT DEFAULT ''",
    'exporter_note': "TEXT DEFAULT ''",
    'rf_ok': 'INTEGER DEFAULT 0',
    'rf_note': "TEXT DEFAULT ''",
    'rf_checked_at': 'TIMESTAMP',
    'xui_version': "TEXT DEFAULT ''",
    'xray_version': "TEXT DEFAULT ''",
    'version_checked_at': 'TIMESTAMP',
    'panel_latest_version': "TEXT DEFAULT ''",
    'xray_latest_version': "TEXT DEFAULT ''",
    'panel_check_error': "TEXT DEFAULT ''",
    'xray_check_error': "TEXT DEFAULT ''",
    'update_checked_at': 'TIMESTAMP',
    'update_state': "TEXT DEFAULT ''",
    'update_kind': "TEXT DEFAULT ''",
    'update_target_version': "TEXT DEFAULT ''",
    'update_started_at': 'TIMESTAMP',
}

TEMPLATE_COLUMNS = {
    'use_in_sub': 'INTEGER DEFAULT 1',
    'provider_label': "TEXT DEFAULT ''",
    'flags': "TEXT DEFAULT ''",
}


LEGACY_TEMPLATE_COLUMNS = {
    'protocol': "TEXT DEFAULT 'vless'",
    'listen': "TEXT DEFAULT ''",
    'security': "TEXT DEFAULT 'reality'",
    'grpc_authority': "TEXT DEFAULT ''",
    'grpc_multi_mode': 'INTEGER DEFAULT 0',
    'xhttp_host': "TEXT DEFAULT ''",
    'xhttp_mode': "TEXT DEFAULT 'auto'",
    'ws_path': "TEXT DEFAULT '/'",
    'ws_host': "TEXT DEFAULT ''",
    'spider_x': "TEXT DEFAULT '/'",
    'short_ids': "TEXT DEFAULT ''",
    'sniffing': 'INTEGER DEFAULT 0',
    'tls_cert_file': "TEXT DEFAULT ''",
    'tls_key_file': "TEXT DEFAULT ''",
    'tls_alpn': "TEXT DEFAULT 'h2,http/1.1'",
    'tls_server_name': "TEXT DEFAULT ''",
    'reject_unknown_sni': 'INTEGER DEFAULT 0',
}


NODEINBOUND_COLUMNS = {
    'snis_locked': 'INTEGER DEFAULT 0',
    'provider_label': "TEXT DEFAULT ''",
}


def _ensure_columns(conn, table: str, columns: dict[str, str]) -> None:
    existing = {row[1] for row in conn.execute(text(f'PRAGMA table_info({table})'))}
    for name, decl in columns.items():
        if name not in existing:
            conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {decl}'))


def init_db(target_engine=None) -> None:
    from app import models  # Register SQLModel tables before create_all.

    with (target_engine or engine).begin() as conn:
        # SQLite DDL and the legacy marker must survive or roll back together.
        conn.exec_driver_sql('BEGIN IMMEDIATE')
        old_tables = set(inspect(conn).get_table_names())
        SQLModel.metadata.create_all(conn)
        if 'node' in old_tables and 'nodetemplateassignment' not in old_tables:
            conn.execute(models.AppSetting.__table__.insert().prefix_with('OR REPLACE').values(
                key='migrate_node_template_assignments', value='pending'))
        _ensure_columns(conn, 'inboundtemplate', {**LEGACY_TEMPLATE_COLUMNS, **TEMPLATE_COLUMNS})
        _ensure_columns(conn, 'node', NODE_COLUMNS)
        _ensure_columns(conn, 'nodeinbound', NODEINBOUND_COLUMNS)
        _ensure_columns(conn, 'client', {'cabinet_account_id': 'TEXT', 'last_online': 'INTEGER DEFAULT 0'})
        conn.execute(text('CREATE UNIQUE INDEX IF NOT EXISTS uq_client_cabinet_account '
                          'ON client(cabinet_account_id) WHERE cabinet_account_id IS NOT NULL'))


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
