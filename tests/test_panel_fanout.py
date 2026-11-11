from app.models import Node
from app.util import flatten_logs, run_parallel
from app.xui import XuiClient


def test_panel_connect_wait_is_shorter_than_the_read():
    node = Node(name='x', panel_url='https://example.invalid', api_token='token')
    with XuiClient(node, timeout=20) as xui:
        assert xui.client.timeout.connect == 3.0
        assert xui.client.timeout.read == 20.0


def test_parallel_keeps_order_and_keeps_going_after_an_error():
    def work(item):
        if item == 'bad':
            raise RuntimeError('нет связи')
        return item

    assert run_parallel(['a', 'bad', 'c'], work)[0] == 'a'
    assert run_parallel(['a', 'bad', 'c'], work)[2] == 'c'
    failed = run_parallel(['a', 'bad', 'c'], work)[1]
    assert isinstance(failed, RuntimeError)
    assert flatten_logs(run_parallel(['a', 'bad'], work)) == ['a', 'нет связи']
