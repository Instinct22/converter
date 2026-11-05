from app.models import Client, Node
from app.overview import aggregate_client_usage, client_is_online
from app.xui import online_emails


def test_online_emails_from_clients_onlines():
    body = {'success': True, 'obj': ['instinct222']}
    assert online_emails(body) == ['instinct222']
    assert online_emails({'success': False, 'obj': []}) is None
    assert online_emails({'success': True, 'obj': [{'email': 'bane139'}]}) == ['bane139']


def test_client_online_if_any_node_reports_email():
    assert client_is_online('instinct222', ['instinct222'])
    assert client_is_online('Instinct222', ['instinct222'])
    assert not client_is_online('instinct22', ['instinct222'])
    client = Client(name='Instinct22', slug='instinct222', uuid='u', sub_token='t')
    nodes = [
        Node(id=1, name='FI', panel_url='https://fi', api_token='a'),
        Node(id=2, name='DE', panel_url='https://de', api_token='a'),
    ]
    probes = {
        1: {'client_rows': [], 'online_emails': ['instinct222']},
        2: {'client_rows': [], 'online_emails': []},
    }
    usage = aggregate_client_usage(client, nodes, probes)
    assert usage['online_nodes'] == 1


def test_usage_sums_traffic_from_client_rows():
    client = Client(name='Bane', slug='bane139', uuid='u', sub_token='t')
    nodes = [
        Node(id=1, name='FI', panel_url='https://fi', api_token='a'),
        Node(id=2, name='DE', panel_url='https://de', api_token='a'),
    ]
    probes = {
        1: {'online_emails': [], 'client_rows': [{'email': 'bane139', 'up': 100, 'down': 400}]},
        2: {'online_emails': ['bane139'], 'client_rows': [{'email': 'bane139', 'up': 50, 'down': 50}]},
    }
    usage = aggregate_client_usage(client, nodes, probes)
    assert usage['used'] == 600
    assert usage['online_nodes'] == 1


def test_presence_probe_counts_without_traffic_rows():
    client = Client(name='Bane', slug='bane139', uuid='u', sub_token='t')
    nodes = [Node(id=3, name='NL', panel_url='https://nl', api_token='a')]
    probes = {3: {'online_emails': ['bane139']}}
    usage = aggregate_client_usage(client, nodes, probes)
    assert usage['online_nodes'] == 1
    assert usage['used'] == 0
