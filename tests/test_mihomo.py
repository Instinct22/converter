from pathlib import Path

from app.mihomo import replace_block
from app.flags import to_emoji, to_iso
from app.xui import (
    _is_missing_route,
    _xui_msg,
    email_from_client_row,
    normalize_panel_url,
    public_host_from_url,
)

SAMPLE = Path(__file__).resolve().parents[1] / 'app' / 'default_mihomo.yaml'


def test_dump_proxies_keeps_list_indent():
    from app.mihomo import dump_proxies

    lines = dump_proxies(
        [
            {
                'name': '🇫🇮 test | 443',
                'type': 'vless',
                'reality-opts': {'public-key': 'pk', 'short-id': 'ab'},
            }
        ]
    )
    assert lines[0] == '- name: 🇫🇮 test | 443'
    assert lines[1] == '  type: vless'
    assert '    public-key: pk' in lines


def test_fallback_group_has_no_direct():
    raw = SAMPLE.read_text(encoding='utf-8')
    fallback = raw.split('name: Reality pool fallback', 1)[1].split('name: PROXY', 1)[0]
    assert 'DIRECT' not in fallback
    from app.bootstrap import strip_fallback_direct

    broken = raw.replace(
        'expected-status: \'204\'\n    use:',
        'expected-status: \'204\'\n    proxies:\n      - DIRECT\n    use:',
        1,
    )
    assert 'proxies:\n      - DIRECT' in broken.split('Reality pool fallback', 1)[1]
    fixed = strip_fallback_direct(broken)
    assert 'DIRECT' not in fixed.split('name: Reality pool fallback', 1)[1].split('name: PROXY', 1)[0]


def test_replace_pool_and_providers():
    raw = SAMPLE.read_text(encoding='utf-8')
    assert 'geox-url:' in raw
    assert '{{XUI_PROVIDERS_BEGIN}}' in raw
    text = replace_block(raw, 'PROVIDERS', ['n1-test:', '  type: http'])
    text = replace_block(text, 'POOL', ['- n1-test'])
    text = replace_block(text, 'TUN_EXCLUDE', ['- 1.2.3.4/32'])
    text = replace_block(text, 'CIDRS', ['- IP-CIDR,1.2.3.4/32,DIRECT,no-resolve'])
    assert text.count('- n1-test') == 2
    assert 'n1-test:' in text
    assert '1.2.3.4/32' in text
    assert '{{XUI_PROVIDERS_BEGIN}}' not in text
    assert '{{XUI_POOL_BEGIN}}' not in text


def test_node_clash_sub_url_matches_3xui():
    from app.mihomo import dump_providers, node_clash_sub_url, provider_name
    from app.models import Node

    node = Node(
        id=1,
        name='test',
        clash_name='Finland-82',
        panel_url='https://82.40.58.78:28879/x',
        public_host='82.40.58.78',
        sub_port=2096,
        sub_clash_path='no1m62cdabx5fb5e',
        sub_scheme='https',
        flag='FI',
    )
    url = node_clash_sub_url(node, '2amob9we0rzfk1z5')
    assert url == 'https://82.40.58.78:2096/no1m62cdabx5fb5e/2amob9we0rzfk1z5'
    dumped = '\n'.join(dump_providers([node], '2amob9we0rzfk1z5')[0])
    assert url in dumped
    assert provider_name(node) in dumped
    assert 'type: http' in dumped


def test_missing_marker_unchanged():
    raw = 'proxies: []\n'
    assert replace_block(raw, 'PROXIES', ['- a']) == raw


def test_xui_error_includes_http_status():
    body = {'success': False, 'msg': '', 'raw': True, 'status': 404}
    assert _is_missing_route(body)
    assert _xui_msg(body, 'addClient failed') == 'HTTP 404'


def test_email_from_nested_client_row():
    assert email_from_client_row({'client': {'email': 'alice'}, 'inboundIds': [1]}) == 'alice'
    assert email_from_client_row({'email': 'bob'}) == 'bob'


def test_reconcile_matching_and_wanted():
    from datetime import datetime, timedelta, timezone

    from app.models import Client
    from app.provision import (
        client_wanted_on_panel,
        is_panel_seed,
        match_master_client,
        panel_client_ident,
    )

    live = Client(
        name='Igor',
        slug='igor',
        uuid='aaa',
        sub_token='tok',
        enable=True,
        expire_at=datetime.now(timezone.utc) + timedelta(days=5),
    )
    dead = Client(
        name='Old',
        slug='old',
        uuid='bbb',
        sub_token='oldtok',
        enable=False,
    )
    clients = [live, dead]
    assert match_master_client(panel_client_ident({'email': 'igor', 'id': 'x'}), clients) is live
    assert match_master_client({'email': 'igor-443-10', 'id': '', 'subId': ''}, clients) is live
    assert match_master_client({'email': 'x', 'id': '', 'subId': 'tok'}, clients) is live
    assert client_wanted_on_panel(live)
    assert not client_wanted_on_panel(dead)
    assert is_panel_seed({'email': 'master-seed-443-ab', 'id': '', 'subId': 'masterseed'})


def test_client_payload_uses_slug_email():
    from app.models import Client
    from app.provision import client_payload

    client = Client(name='Igor', slug='igor', uuid='u', sub_token='t')
    assert client_payload(client)['email'] == 'igor'


def test_normalize_panel_url_strips_ui_suffix():
    assert (
        normalize_panel_url('https://82.40.58.78:28879/l156n0rG5HBRse0B01/panel')
        == 'https://82.40.58.78:28879/l156n0rG5HBRse0B01'
    )
    assert public_host_from_url('https://82.40.58.78:28879/l156n0rG5HBRse0B01/panel') == '82.40.58.78'


def test_format_bytes_and_cpu():
    from app.util import cpu_percent, format_bytes

    assert format_bytes(0) == '0 Б'
    assert format_bytes(1536) == '1.5 КБ'
    assert cpu_percent(0.42) == 42
    assert cpu_percent(87) == 87


def test_providers_expand_snis_and_ports():
    from app.mihomo import dump_providers
    from app.models import Node, NodeInbound

    node = Node(
        id=1,
        name='Finland-82',
        clash_name='Finland-82',
        panel_url='https://82.40.58.78:2053/',
        public_host='82.40.58.78',
        sub_port=2096,
        sub_clash_path='no1m62cdabx5fb5e',
        flag='FI',
    )
    grpc = NodeInbound(
        id=1,
        node_id=1,
        xui_inbound_id=1,
        port=443,
        protocol='vless',
        network='grpc',
        server_names='gitlab.com,auth.gitlab.com,gprd.gitlab.com',
        use_in_sub=True,
    )
    xhttp = NodeInbound(
        id=2,
        node_id=1,
        xui_inbound_id=2,
        port=8443,
        protocol='vless',
        network='xhttp',
        server_names='www.yahoo.com,news.yahoo.com',
        extra_snis='news.yahoo.com',
        use_in_sub=True,
    )
    lines, keys = dump_providers([node], 'tok', {1: [grpc, xhttp]})
    text = '\n'.join(lines)
    assert keys[0] == 'n1-finland-82'
    assert 'n1-finland-82-auth' in keys
    assert 'n1-finland-82-gprd' in keys
    assert 'n1-finland-82-yahoo' in keys
    assert 'n1-finland-82-yahoo-news' in keys
    assert "filter: '443-'" in text
    assert "exclude-filter: '8443'" in text
    assert 'n1-finland-82:\n  name: n1-finland-82' in text
    assert '.name = "🇫🇮 Finland-82"' in text
    assert text.index("filter: '443-'") < text.index('n1-finland-82-auth')
    assert 'auth.gitlab.com' in text
    assert 'news.yahoo.com' in text
    assert "filter: '8443'" in text
    assert 'n1-finland-82-yahoo-ymail' not in keys
    assert text.count('url: "https://') == len(keys)


def test_inbound_sni_chain_skips_unrelated_sans():
    from app.mihomo import inbound_sni_chain
    from app.models import NodeInbound

    inbound = NodeInbound(
        node_id=1,
        xui_inbound_id=2,
        port=8443,
        network='xhttp',
        server_names='www.yahoo.com,ymail.com,de.yahoo.com,news.yahoo.com',
        extra_snis='',
    )
    assert inbound_sni_chain(inbound) == [
        'www.yahoo.com',
        'de.yahoo.com',
        'news.yahoo.com',
    ]


def test_resolve_clash_sub_path_prefers_working_segment():
    from unittest.mock import MagicMock, patch

    from app.models import Node
    from app.provision import resolve_clash_sub_path

    node = Node(
        public_host='195.231.86.20',
        sub_port=2096,
        sub_scheme='https',
        sub_clash_path='mrilr3ht4imylp2d',
        sub_path='9uguw9puuwfjepee',
    )

    def fake_get(url, headers=None):
        response = MagicMock()
        if 'mrilr3ht4imylp2d' in url:
            response.status_code = 404
            response.headers = {'content-type': 'text/plain'}
            response.text = '404 page not found'
        else:
            response.status_code = 200
            response.headers = {'content-type': 'application/yaml'}
            response.text = 'proxies:\n- name: x'
        return response

    with patch('app.provision.httpx.Client') as client_cls:
        client_cls.return_value.__enter__.return_value.get.side_effect = fake_get
        assert resolve_clash_sub_path(node, 'tok') == '9uguw9puuwfjepee'


def test_published_snis_from_inbound_only():
    from app.mihomo import published_snis
    from app.models import NodeInbound

    inbound = NodeInbound(
        node_id=1,
        xui_inbound_id=1,
        server_names='gitlab.com, auth.gitlab.com',
        extra_snis='news.yahoo.com',
        use_global_sni=True,
    )
    assert published_snis(inbound, ['gprd.gitlab.com']) == ['gitlab.com', 'auth.gitlab.com']


def test_match_client_row_accepts_slug_email():
    from app.overview import client_is_online, match_client_row

    assert match_client_row('igor', 'uuid-1', {'email': 'igor', 'uuid': ''})
    assert match_client_row('igor', 'uuid-1', {'email': 'igor-443-10', 'uuid': ''})
    assert match_client_row('igor', 'uuid-1', {'email': 'other', 'uuid': 'uuid-1'})
    assert not match_client_row('igor', 'uuid-1', {'email': 'igortest', 'uuid': ''})
    assert client_is_online('igor', ['igor'])
    assert client_is_online('igor', ['igor-443-10'])
    assert not client_is_online('igor', ['other'])


def test_wants_html_for_browser_yaml_for_clients():
    from types import SimpleNamespace

    from app.routers.sub import wants_subscription_html

    def req(ua='', accept='', **q):
        return SimpleNamespace(headers={'user-agent': ua, 'accept': accept}, query_params=q)

    assert wants_subscription_html(req('Mozilla/5.0', 'text/html'))
    assert not wants_subscription_html(req('clash.meta/1.0', 'text/html'))
    assert not wants_subscription_html(req('Mihomo/1', '*/*'))
    assert not wants_subscription_html(req('Mozilla/5.0', 'text/html', yaml='1'))
    assert wants_subscription_html(req('curl/8', '*/*', html='1'))


def test_subscription_url_and_headers():
    from app.mihomo import subscription_headers
    from app.models import Client
    from app.sub_link import client_sub_url

    client = Client(name='Igor', slug='igor', uuid='u', sub_token='2amob9we0rzfk1z5')
    url = client_sub_url(client)
    assert url.endswith('/2amob9we0rzfk1z5')
    assert '/clash/' not in url
    headers = subscription_headers(client, upload=10, download=20)
    assert 'upload=10; download=20' in headers['subscription-userinfo']
    assert headers['profile-update-interval'] == '1'


def test_flag_iso_roundtrip():
    assert to_iso('FI') == 'FI'
    assert to_iso('🇫🇮') == 'FI'
    assert to_emoji('FI') == '🇫🇮'


def test_parse_dest_and_cert_sans():
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    from app.tls_sni import names_from_certificate, parse_dest

    assert parse_dest('gitlab.com') == ('gitlab.com', 443)
    assert parse_dest('www.yahoo.com:443') == ('www.yahoo.com', 443)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'gitlab.com')])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName('gitlab.com'),
                    x509.DNSName('www.gitlab.com'),
                    x509.DNSName('*.gitlab.com'),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    exact, wild = names_from_certificate(cert)
    assert exact == ['gitlab.com', 'www.gitlab.com']
    assert wild == ['*.gitlab.com']
    assert 'auth.gitlab.com' not in exact
