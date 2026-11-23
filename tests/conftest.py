"""Keep integration tests away from the deployment's database, keys and users."""
from tempfile import TemporaryDirectory
from pathlib import Path

import pytest


def pytest_configure(config):
    config._xui_tmp = TemporaryDirectory(prefix='xui-tests-')
    directory = Path(config._xui_tmp.name)
    config._xui_env = pytest.MonkeyPatch()
    for key, value in {
        'XUI_DATA_DIR': str(directory),
        'DATABASE_URL': f'sqlite:///{directory.as_posix()}/master.db',
        'ADMIN_USERNAME': 'test-admin',
        'ADMIN_PASSWORD': 'test-suite-only',
        'SESSION_SECRET': 'test-suite-secret',
        'PUBLIC_BASE_URL': 'http://testserver',
        'SUB_PATH': 'test-sub',
    }.items():
        config._xui_env.setenv(key, value)


def pytest_unconfigure(config):
    from app.database import engine

    engine.dispose()
    config._xui_env.undo()
    config._xui_tmp.cleanup()
