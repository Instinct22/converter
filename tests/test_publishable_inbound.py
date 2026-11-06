from app.mihomo import _publishable_inbound
from app.models import NodeInbound


def test_publishable_skips_test_ports():
    assert _publishable_inbound(
        NodeInbound(node_id=1, xui_inbound_id=1, port=443, use_in_sub=True)
    )
    assert not _publishable_inbound(
        NodeInbound(node_id=1, xui_inbound_id=2, port=49579, use_in_sub=True)
    )
    assert _publishable_inbound(
        NodeInbound(node_id=1, xui_inbound_id=3, port=2083, use_in_sub=True, snis_locked=True)
    )
    assert not _publishable_inbound(
        NodeInbound(node_id=1, xui_inbound_id=4, port=2083, use_in_sub=False, snis_locked=True)
    )
