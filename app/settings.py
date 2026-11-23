import os
import secrets
import tempfile
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get('XUI_DATA_DIR') or ROOT / 'data')
DATA_DIR.mkdir(exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / '.env',
        env_file_encoding='utf-8',
        extra='ignore',
    )

    admin_username: str = 'admin'
    admin_password: str = ''
    session_secret: str = ''
    public_base_url: str = 'http://127.0.0.1:8080'
    master_ip: str = '5.180.174.204'
    update_base_url: str = 'https://api.aegis-gate.ru'
    sub_path: str = ''
    host: str = '0.0.0.0'
    port: int = 8080
    database_url: str = f'sqlite:///{(DATA_DIR / "master.db").as_posix()}'

    def validate_admin_password(self) -> None:
        if self.admin_password.strip() in {'', 'changeme'}:
            raise ValueError('Задайте собственный ADMIN_PASSWORD перед запуском Master')


settings = Settings()


def session_signing_key() -> str:
    if settings.session_secret.strip():
        return settings.session_secret.strip()
    path = DATA_DIR / 'session_secret'
    if not path.exists():
        with tempfile.NamedTemporaryFile(dir=DATA_DIR, delete=False) as temporary:
            temp_path = Path(temporary.name)
            temporary.write(secrets.token_urlsafe(48).encode('ascii'))
        try:
            os.link(temp_path, path)
        except FileExistsError:
            pass  # Another worker published its complete key first.
        finally:
            temp_path.unlink()
    path.chmod(0o600)
    stored = path.read_text(encoding='utf-8').strip()
    if not stored:
        raise RuntimeError('Файл session_secret пуст')
    return stored
