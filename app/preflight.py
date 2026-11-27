"""Check a candidate image against a SQLite snapshot before replacing Master."""
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import make_url
from sqlmodel import Session, create_engine, select

from app import database, ssh_access
from app.bootstrap import seed_if_empty
from app.models import Node
from app.provision import ensure_default_node_templates
from app.settings import settings
from app.xui import XuiClient
from app.xui_install import migrate_install_logs


def check_nodes(session):
    errors = []
    for node in session.exec(select(Node).order_by(Node.id)):
        if 'installing' in (node.install_state, node.exporter_state) or node.update_state == 'running':
            errors.append(f'Нода {node.id}: дождитесь завершения текущей операции')
        if ssh_access.resolved_auth(node) != ssh_access.AUTH_NONE and not node.needs_install_host_key():
            host, _, port = ssh_access._target(node)
            with ssh_access.trusted_ssh_client(host, port) as client:
                if not client.get_host_keys().lookup(ssh_access.host_key_name(host, port)):
                    errors.append(f'Нода {node.id}: отсутствует проверенный ключ SSH в known_hosts')
            if ssh_access.resolved_auth(node) == ssh_access.AUTH_KEY and not ssh_access.key_file_exists():
                errors.append(f'Нода {node.id}: отсутствует приватный ключ флота')
        if node.enabled and not node.is_grafana():
            try:
                with XuiClient(node, timeout=5.0) as panel:
                    panel.inbounds()
            except Exception as exc:
                # Panel responses and URLs can contain credentials.
                errors.append(f'Нода {node.id}: не удалось прочитать входы ({type(exc).__name__}). '
                              'Проверьте адрес, TLS, токен и доступность панели.')
    return errors


def check_database(source: Path):
    with tempfile.TemporaryDirectory(prefix='xui-preflight-') as directory:
        copy = Path(directory) / 'snapshot.db'
        if source.is_file():
            with closing(sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True)) as live:
                with closing(sqlite3.connect(copy)) as snapshot:
                    live.backup(snapshot)
        engine = create_engine(f'sqlite:///{copy.as_posix()}')
        event.listen(engine, 'connect', database._sqlite_pragma)
        try:
            database.init_db(engine)
            with Session(engine) as session:
                if session.execute(text('PRAGMA quick_check')).scalars().all() != ['ok']:
                    return ['SQLite: не прошла проверка целостности']
                if session.execute(text('PRAGMA foreign_key_check')).first():
                    return ['SQLite: найдены нарушенные внешние ключи']
                migrate_install_logs(session)
                seed_if_empty(session)
                ensure_default_node_templates(session)
                return check_nodes(session)
        finally:
            engine.dispose()


def main() -> int:
    settings.validate_admin_password()
    url = make_url(settings.database_url)
    if url.get_backend_name() != 'sqlite' or not url.database:
        raise ValueError('Для проверки нужен путь к SQLite Master')
    problems = check_database(Path(url.database))
    for message in problems:
        print(message)
    if problems:
        return 1
    print('Проверены настройки Master, миграции на копии SQLite и доступ к активным панелям.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
