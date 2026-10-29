from collections.abc import Generator

from sqlalchemy import event, text
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
    cursor.close()


NODE_COLUMNS = {
    'sub_port': 'INTEGER DEFAULT 2096',
    'sub_path': "TEXT DEFAULT ''",
    'sub_clash_path': "TEXT DEFAULT ''",
    'sub_scheme': "TEXT DEFAULT 'https'",
}

TEMPLATE_COLUMNS = {
    'use_in_sub': 'INTEGER DEFAULT 1',
    'provider_label': "TEXT DEFAULT ''",
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


def _ensure_columns(table: str, columns: dict[str, str]) -> None:
    with engine.begin() as conn:
        existing = {row[1] for row in conn.execute(text(f'PRAGMA table_info({table})'))}
        for name, decl in columns.items():
            if name not in existing:
                conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {name} {decl}'))


NODEINBOUND_COLUMNS = {
    'snis_locked': 'INTEGER DEFAULT 0',
    'provider_label': "TEXT DEFAULT ''",
}


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    _ensure_columns('inboundtemplate', {**LEGACY_TEMPLATE_COLUMNS, **TEMPLATE_COLUMNS})
    _ensure_columns('node', NODE_COLUMNS)
    _ensure_columns('nodeinbound', NODEINBOUND_COLUMNS)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
