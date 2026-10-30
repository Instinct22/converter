from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from app.models import Node


class XuiError(RuntimeError):
    pass


def normalize_panel_url(url: str) -> str:
    value = (url or '').strip().rstrip('/')
    if value.lower().endswith('/panel'):
        value = value[: -len('/panel')].rstrip('/')
    return value


def public_host_from_url(url: str) -> str:
    parsed = urlparse(normalize_panel_url(url))
    return parsed.hostname or ''


class XuiClient:
    def __init__(self, node: Node, timeout: float = 25.0) -> None:
        self.node = node
        self.base = normalize_panel_url(node.panel_url)
        headers = {'Accept': 'application/json'}
        token = (node.api_token or '').strip()
        if token:
            headers['Authorization'] = f'Bearer {token}'
        self.client = httpx.Client(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers=headers,
        )
        self._logged_in = bool(token)

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> XuiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def login(self) -> None:
        if self._logged_in:
            return
        token = (self.node.api_token or '').strip()
        if token:
            self._logged_in = True
            return
        raise XuiError('у сервера нет API Token')

    def call(
        self,
        path: str,
        data: Any = None,
        method: str | None = None,
    ) -> dict[str, Any]:
        self.login()
        url = f'{self.base}{path}'
        verb = method or ('POST' if data is not None else 'GET')
        if verb == 'GET':
            r = self.client.get(url)
        else:
            r = self.client.post(url, json=data if data is not None else {})
        body = _as_json(r)
        if r.status_code == 404 and not body and path.startswith('/panel/api/'):
            raise XuiError(
                'панель не приняла API Token. В 3x-ui 3.5 нужен токен из '
                'Settings → Security → API Token'
            )
        if r.status_code >= 400 and not body:
            raise XuiError(f'{path} HTTP {r.status_code}')
        return body

    def panel_settings(self) -> dict[str, Any]:
        body = self.call('/panel/api/setting/all', {})
        if body.get('success') and isinstance(body.get('obj'), dict):
            return body['obj']
        raise XuiError(_xui_msg(body, 'setting/all failed'))

    def inbounds(self) -> list[dict[str, Any]]:
        for method, data in (('GET', None), ('POST', {})):
            body = self.call('/panel/api/inbounds/list', data=data, method=method)
            if body.get('success'):
                obj = body.get('obj') or []
                return obj if isinstance(obj, list) else []
        raise XuiError('inbounds/list failed')

    def add_inbound(self, spec: dict[str, Any]) -> dict[str, Any]:
        body = self.call('/panel/api/inbounds/add', spec)
        if not body.get('success'):
            raise XuiError(body.get('msg') or 'add inbound failed')
        return body

    def update_inbound(self, inbound_id: int, spec: dict[str, Any]) -> dict[str, Any]:
        payload = dict(spec)
        payload['id'] = inbound_id
        body = self.call(f'/panel/api/inbounds/update/{inbound_id}', payload)
        if not body.get('success'):
            raise XuiError(body.get('msg') or 'update inbound failed')
        return body

    def del_inbound(self, inbound_id: int) -> dict[str, Any]:
        body = self.call(f'/panel/api/inbounds/del/{inbound_id}', {})
        if body.get('success') is False:
            raise XuiError(body.get('msg') or 'del inbound failed')
        return body

    def restart_xray(self) -> dict[str, Any]:
        body = self.call('/panel/api/server/restartXrayService', {})
        if body.get('success') is False:
            raise XuiError(body.get('msg') or 'restart xray failed')
        return body

    def server_logs(self, count: int = 80) -> str:
        chunks: list[str] = []
        for path, method, data in (
            ('/panel/api/server/status', 'GET', None),
            (f'/panel/api/server/logs/{int(count)}', 'GET', None),
            (f'/panel/api/server/log/{int(count)}', 'GET', None),
            ('/panel/api/server/xrayLogs', 'POST', {}),
        ):
            try:
                body = self.call(path, data=data, method=method)
            except XuiError as exc:
                chunks.append(f'{path}: {exc}')
                continue
            text = body.get('obj')
            if isinstance(text, (dict, list)):
                text = json.dumps(text, ensure_ascii=False)[:2000]
            chunks.append(f'## {path}\n{text or json.dumps(body, ensure_ascii=False)[:1500]}')
        return '\n'.join(chunks)

    def add_client(
        self,
        inbound_ids: int | list[int],
        client: dict[str, Any],
    ) -> dict[str, Any]:
        ids = _as_ids(inbound_ids)
        body = self.call(
            '/panel/api/clients/add',
            {'client': client, 'inboundIds': ids},
        )
        if body.get('success'):
            return body
        if _is_missing_route(body):
            last: dict[str, Any] = {}
            for inbound_id in ids:
                last = self.call(
                    '/panel/api/inbounds/addClient',
                    {
                        'id': inbound_id,
                        'settings': json.dumps({'clients': [client]}),
                    },
                )
                if not last.get('success'):
                    raise XuiError(_xui_msg(last, 'addClient failed'))
            return last
        raise XuiError(_xui_msg(body, 'addClient failed'))

    def update_client(
        self,
        email: str,
        client: dict[str, Any],
        inbound_id: int | None = None,
    ) -> dict[str, Any]:
        body = self.call(f'/panel/api/clients/update/{_path_id(email)}', client)
        if body.get('success'):
            return body
        uuid = str(client.get('id') or '')
        if inbound_id is not None and uuid and _is_missing_route(body):
            payload = {'id': inbound_id, 'settings': json.dumps({'clients': [client]})}
            body = self.call(f'/panel/api/inbounds/updateClient/{uuid}', payload)
            if body.get('success'):
                return body
        raise XuiError(_xui_msg(body, 'updateClient failed'))

    def attach_client(self, email: str, inbound_ids: int | list[int]) -> dict[str, Any]:
        ids = _as_ids(inbound_ids)
        body = self.call(
            f'/panel/api/clients/{_path_id(email)}/attach',
            {'inboundIds': ids},
        )
        if body.get('success'):
            return body
        if _is_missing_route(body):
            return {'success': True, 'msg': 'attach skipped'}
        raise XuiError(_xui_msg(body, 'attach failed'))

    def list_clients(self) -> list[dict[str, Any]]:
        body = self.call('/panel/api/clients/list')
        if body.get('success'):
            obj = body.get('obj')
            if isinstance(obj, list):
                return [item for item in obj if isinstance(item, dict)]
            if isinstance(obj, dict):
                rows = obj.get('clients') or obj.get('list') or []
                if isinstance(rows, list):
                    return [item for item in rows if isinstance(item, dict)]
            return []
        if not _is_missing_route(body):
            raise XuiError(_xui_msg(body, 'clients/list failed'))
        collected: list[dict[str, Any]] = []
        for inbound in self.inbounds():
            settings = as_obj(inbound.get('settings')) or {}
            if not isinstance(settings, dict):
                continue
            for item in settings.get('clients') or []:
                if isinstance(item, dict):
                    collected.append(item)
        return collected

    def clients_by_sub(self, sub_id: str) -> list[dict[str, Any]]:
        body = self.call(f'/panel/api/clients/get/subId/{_path_id(sub_id)}')
        if not body.get('success'):
            return []
        obj = body.get('obj')
        if isinstance(obj, list):
            return [item for item in obj if isinstance(item, dict)]
        if isinstance(obj, dict):
            return [obj]
        return []

    def del_client(self, inbound_id: int, client_uuid: str, email: str = '') -> dict[str, Any]:
        if email:
            body = self.call(f'/panel/api/clients/del/{_path_id(email)}', {})
            if body.get('success'):
                return body
            if not _is_missing_route(body):
                msg = _xui_msg(body, 'delClient failed')
                if _is_absent(msg):
                    return {'success': True, 'msg': 'already gone'}
                raise XuiError(msg)
        body = self.call(f'/panel/api/inbounds/{inbound_id}/delClient/{client_uuid}', {})
        if body.get('success'):
            return body
        if email:
            body = self.call(
                f'/panel/api/inbounds/{inbound_id}/delClient/{_path_id(email)}',
                {},
            )
        if not body.get('success'):
            msg = _xui_msg(body, 'delClient failed')
            if _is_absent(msg):
                return {'success': True, 'msg': 'already gone'}
            raise XuiError(msg)
        return body

    def server_status(self) -> dict[str, Any]:
        body = self.call('/panel/api/server/status')
        if not body.get('success'):
            raise XuiError(body.get('msg') or 'status failed')
        return body.get('obj') or {}

    def get_inbound(self, inbound_id: int) -> dict[str, Any]:
        body = self.call(f'/panel/api/inbounds/get/{inbound_id}')
        if not body.get('success'):
            raise XuiError(body.get('msg') or 'get inbound failed')
        obj = body.get('obj') or {}
        return obj if isinstance(obj, dict) else {}

    def update_inbound(self, inbound_id: int, spec: dict[str, Any]) -> dict[str, Any]:
        body = self.call(f'/panel/api/inbounds/update/{inbound_id}', spec)
        if not body.get('success'):
            raise XuiError(body.get('msg') or 'update inbound failed')
        return body

    def onlines(self) -> list[str]:
        # 3x-ui 2.6+ отдаёт онлайн с /clients/onlines. Старый /inbounds/onlines
        # на этих панелях отвечает 404, и обзор видел всех офлайн.
        for path in ('/panel/api/clients/onlines', '/panel/api/inbounds/onlines'):
            for method, data in (('POST', {}), ('GET', None)):
                try:
                    body = self.call(path, data=data, method=method)
                except XuiError:
                    continue
                emails = online_emails(body)
                if emails is not None:
                    return emails
        return []


def online_emails(body: Any) -> list[str] | None:
    """Email клиентов в сети. None — этот ответ не про онлайн."""
    if not isinstance(body, dict) or not body.get('success'):
        return None
    obj = body.get('obj')
    if obj is None:
        return []
    if isinstance(obj, list):
        emails: list[str] = []
        for item in obj:
            if isinstance(item, str) and item.strip():
                emails.append(item.strip())
            elif isinstance(item, dict):
                email = str(item.get('email') or '').strip()
                if email:
                    emails.append(email)
        return emails
    if isinstance(obj, dict):
        nested = obj.get('emails') or obj.get('obj')
        if isinstance(nested, list):
            return [str(item).strip() for item in nested if str(item).strip()]
    return None


def _as_ids(inbound_ids: int | list[int]) -> list[int]:
    if isinstance(inbound_ids, int):
        return [inbound_ids]
    return [int(item) for item in inbound_ids]


def _path_id(value: str) -> str:
    return quote(str(value or ''), safe='')


def _is_missing_route(body: dict[str, Any]) -> bool:
    return bool(body.get('raw')) and int(body.get('status') or 0) in {404, 405}


def _is_absent(msg: str) -> bool:
    low = (msg or '').lower()
    return 'not found' in low or 'does not exist' in low or 'no client' in low


def _xui_msg(body: dict[str, Any], fallback: str) -> str:
    msg = str(body.get('msg') or '').strip()
    status = body.get('status')
    if body.get('raw') and status:
        extra = f'HTTP {status}'
        return f'{msg} ({extra})' if msg else extra
    return msg or fallback


def email_from_client_row(row: dict[str, Any]) -> str:
    inner = row.get('client') if isinstance(row.get('client'), dict) else row
    if isinstance(inner, dict):
        return str(inner.get('email') or '')
    return ''


def _as_json(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except Exception:
        return {
            'success': False,
            'msg': (response.text or '')[:300],
            'raw': True,
            'status': response.status_code,
        }
    return data if isinstance(data, dict) else {'success': False, 'msg': str(data)}


def as_obj(value: Any) -> Any:
    if isinstance(value, str) and value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value
