import json

from fastapi.testclient import TestClient

from app.main import app
from app.routers import updates
from app.settings import settings


def _login(client: TestClient) -> None:
    response = client.post(
        '/login',
        data={'username': settings.admin_username, 'password': settings.admin_password},
        follow_redirects=False,
    )
    assert response.status_code == 302


def test_latest_is_public_and_empty_without_a_catalog(monkeypatch, tmp_path):
    monkeypatch.setattr(updates, 'catalog_path', lambda: tmp_path / 'catalog.json')
    client = TestClient(app)
    response = client.get('/api/app/latest', params={'platform': 'windows', 'arch': 'amd64'})
    assert response.status_code == 200
    assert response.json() == {'update': False}


def test_latest_points_at_the_update_host(monkeypatch, tmp_path):
    files = tmp_path / 'files'
    files.mkdir()
    name = 'AegisGate-1.1.6-windows-amd64-setup.exe'
    (files / name).write_bytes(b'installer')
    catalog = {
        'stable': {
            'windows': {
                'amd64': {
                    'version': '1.1.6',
                    'notes': 'fix',
                    'filename': name,
                    'sha256': 'ab' * 32,
                },
            },
        },
    }
    (tmp_path / 'catalog.json').write_text(json.dumps(catalog), encoding='utf-8')
    monkeypatch.setattr(updates, 'catalog_path', lambda: tmp_path / 'catalog.json')
    monkeypatch.setattr(updates, 'files_dir', lambda: files)
    client = TestClient(app)
    response = client.get(
        '/api/app/latest',
        params={'platform': 'windows', 'arch': 'amd64', 'channel': 'stable'},
    )
    body = response.json()
    assert body['update'] is True
    assert body['url'] == f'https://api.aegis-gate.ru/api/app/download/{name}'
    assert body['sha256'] == 'ab' * 32
    downloaded = client.get(f'/api/app/download/{name}')
    assert downloaded.status_code == 200
    assert downloaded.content == b'installer'


def test_release_page_lists_files_and_delete_unpublishes_the_current_one(monkeypatch, tmp_path):
    files = tmp_path / 'files'
    files.mkdir()
    current = 'AegisGate-1.0.4-windows-amd64-setup.exe'
    old = 'AegisGate-1.0.0-windows-amd64-setup.exe'
    (files / current).write_bytes(b'new')
    (files / old).write_bytes(b'old')
    (files / 'notes.txt').write_text('ignore', encoding='utf-8')
    catalog = {
        'stable': {
            'windows': {
                'amd64': {
                    'version': '1.0.4',
                    'notes': 'заметки релиза',
                    'filename': current,
                    'sha256': 'ab' * 32,
                },
            },
        },
    }
    (tmp_path / 'catalog.json').write_text(json.dumps(catalog), encoding='utf-8')
    monkeypatch.setattr(updates, 'catalog_path', lambda: tmp_path / 'catalog.json')
    monkeypatch.setattr(updates, 'files_dir', lambda: files)
    client = TestClient(app)

    assert client.delete(f'/api/releases/{old}').status_code == 401
    _login(client)
    page = client.get('/releases')
    assert page.status_code == 200
    assert current in page.text
    assert old in page.text
    assert 'notes.txt' not in page.text
    assert 'заметки релиза' in page.text
    assert 'текущий 1.0.4' in page.text

    removed = client.delete(f'/api/releases/{old}')
    assert removed.status_code == 200
    assert removed.json()['unpublished'] is False
    assert not (files / old).exists()
    still = client.get('/api/app/latest', params={'platform': 'windows', 'arch': 'amd64'})
    assert still.json()['version'] == '1.0.4'

    dropped = client.delete(f'/api/releases/{current}')
    assert dropped.status_code == 200
    assert dropped.json()['unpublished'] is True
    assert not (files / current).exists()
    latest = client.get('/api/app/latest', params={'platform': 'windows', 'arch': 'amd64'})
    assert latest.json() == {'update': False}
    assert client.get(f'/api/app/download/{current}').status_code == 404


def test_download_rejects_a_path_outside_the_files_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(updates, 'files_dir', lambda: tmp_path)
    client = TestClient(app)
    response = client.get('/api/app/download/..%2Fsecret')
    assert response.status_code == 404
