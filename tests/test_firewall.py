from app.firewall import firewall_actions, protected_ports
from app.models import Node


def test_firewall_opens_inbound_and_keeps_service_ports():
    node = Node(
        name='EE',
        panel_url='https://179.254.190.75:21096/secret',
        api_token='t',
        public_host='179.254.190.75',
        sub_port=2096,
        ssh_port=22,
    )
    assert protected_ports(node) == {22, 80, 2096, 21096}
    actions = firewall_actions(node, {2083, 443}, {8443, 22, 2096, 21096, 80, 2083})
    assert ('allow', 443) in actions
    assert ('allow', 2083) in actions
    assert ('delete', 8443) in actions
    assert all(port not in {22, 80, 2096, 21096} for kind, port in actions if kind == 'delete')
