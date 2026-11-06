import secrets
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / 'data'
DATA_DIR.mkdir(exist_ok=True)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / '.env',
        env_file_encoding='utf-8',
        extra='ignore',
    )

    admin_username: str = 'admin'
    admin_password: str = 'changeme'
    session_secret: str = ''
    public_base_url: str = 'http://127.0.0.1:8080'
    master_ip: str = '5.180.174.204'
    update_base_url: str = 'https://api.aegis-gate.ru'
    sub_path: str = ''
    host: str = '0.0.0.0'
    port: int = 8080
    database_url: str = f'sqlite:///{(DATA_DIR / "master.db").as_posix()}'


settings = Settings()


def session_signing_key() -> str:
    if settings.session_secret.strip():
        return settings.session_secret.strip()
    path = DATA_DIR / 'session_secret'
    if path.exists():
        stored = path.read_text(encoding='utf-8').strip()
        if stored:
            return stored
    key = secrets.token_urlsafe(48)
    path.write_text(key, encoding='utf-8')
    return key
