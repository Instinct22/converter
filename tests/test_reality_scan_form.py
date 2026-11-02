import httpx

from app.models import Node
from app.xui import XuiClient


def test_scan_reality_target_posts_form_fields():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen['content_type'] = request.headers.get('content-type', '')
        seen['body'] = request.content.decode()
        return httpx.Response(200, json={
            'success': True,
            'obj': {'latencyMs': 18, 'feasible': True, 'target': 'www.apple.com:443'},
        })

    node = Node(name='Estonia-01', panel_url='https://panel.example', api_token='token')
    client = XuiClient(node, timeout=5)
    original = client.client
    client.client = httpx.Client(transport=httpx.MockTransport(handler), headers=original.headers)
    try:
        payload = client.scan_reality_target('www.apple.com:443', 'www.apple.com')
    finally:
        client.close()
        original.close()

    assert payload['feasible'] is True
    assert 'application/x-www-form-urlencoded' in seen['content_type']
    assert 'target=www.apple.com%3A443' in seen['body']
    assert 'sni=www.apple.com' in seen['body']
    assert 'allowPrivate=false' in seen['body']
