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

    admin_password: str = 'changeme'
    session_secret: str = 'dev-session-secret-change-me'
    public_base_url: str = 'http://127.0.0.1:8080'
    sub_path: str = ''
    host: str = '0.0.0.0'
    port: int = 8080
    database_url: str = f'sqlite:///{(DATA_DIR / "master.db").as_posix()}'


settings = Settings()
