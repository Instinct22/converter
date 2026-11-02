import json

from fastapi.testclient import TestClient

from app.main import app
from app.routers import updates


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


def test_download_rejects_a_path_outside_the_files_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(updates, 'files_dir', lambda: tmp_path)
    client = TestClient(app)
    response = client.get('/api/app/download/..%2Fsecret')
    assert response.status_code == 404
