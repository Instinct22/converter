from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.database import engine, init_db
from app.main import app
from app.models import Client
from app.settings import settings


def _login(client: TestClient) -> None:
    response = client.post(
        '/login',
        data={'username': settings.admin_username, 'password': settings.admin_password},
        follow_redirects=False,
    )
    assert response.status_code == 302


def _delete_account(account_id: str) -> None:
    with Session(engine) as session:
        row = session.exec(
            select(Client).where(Client.cabinet_account_id == account_id)
        ).first()
        if row is not None:
            session.delete(row)
            session.commit()


def test_same_cabinet_account_does_not_create_a_second_client(monkeypatch):
    monkeypatch.setattr('app.routers.api.provision_client', lambda *args, **kwargs: [])
    init_db()
    account_id = 'cab-test-same'
    _delete_account(account_id)
    client = TestClient(app)
    _login(client)
    body = {'name': 'Демо', 'days': 0, 'cabinet_account_id': account_id}
    try:
        first = client.post('/api/clients', json=body)
        second = client.post('/api/clients', json={**body, 'name': 'Другое имя'})
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()['created'] is True
        assert second.json()['created'] is False
        assert second.json()['client']['id'] == first.json()['client']['id']
        assert second.json()['client']['sub_token'] == first.json()['client']['sub_token']
        assert second.json()['client']['sub_url'] == first.json()['client']['sub_url']
        assert second.json()['client']['name'] == 'Демо'
        assert '/cab-test-same' not in first.json()['client']['sub_url']
        found = client.get(f'/api/clients/by-cabinet/{account_id}')
        assert found.status_code == 200
        assert found.json()['client']['id'] == first.json()['client']['id']
    finally:
        _delete_account(account_id)


def test_different_cabinet_accounts_get_different_clients(monkeypatch):
    monkeypatch.setattr('app.routers.api.provision_client', lambda *args, **kwargs: [])
    init_db()
    first_id = 'cab-test-one'
    second_id = 'cab-test-two'
    _delete_account(first_id)
    _delete_account(second_id)
    client = TestClient(app)
    _login(client)
    try:
        first = client.post(
            '/api/clients',
            json={'name': 'Первый', 'days': 0, 'cabinet_account_id': first_id},
        )
        second = client.post(
            '/api/clients',
            json={'name': 'Второй', 'days': 0, 'cabinet_account_id': second_id},
        )
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()['created'] is True
        assert second.json()['created'] is True
        assert first.json()['client']['id'] != second.json()['client']['id']
        assert first.json()['client']['sub_token'] != second.json()['client']['sub_token']
    finally:
        _delete_account(first_id)
        _delete_account(second_id)


def test_clients_without_cabinet_account_stay_independent(monkeypatch):
    monkeypatch.setattr('app.routers.api.provision_client', lambda *args, **kwargs: [])
    init_db()
    client = TestClient(app)
    _login(client)
    created_ids = []
    try:
        for name in ('Без привязки А', 'Без привязки Б'):
            response = client.post('/api/clients', json={'name': name, 'days': 0})
            assert response.status_code == 200
            assert response.json()['created'] is True
            assert response.json()['client']['cabinet_account_id'] is None
            created_ids.append(response.json()['client']['id'])
        assert created_ids[0] != created_ids[1]
    finally:
        with Session(engine) as session:
            for client_id in created_ids:
                row = session.get(Client, client_id)
                if row is not None:
                    session.delete(row)
            session.commit()
