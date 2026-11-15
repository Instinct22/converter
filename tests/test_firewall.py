from app.firewall import _script, firewall_plan, protected_ports, wanted_ports
from app.models import Node


def _node() -> Node:
    return Node(
        name='EE',
        panel_url='https://179.254.190.75:21096/secret',
        api_token='t',
        public_host='179.254.190.75',
        sub_port=2096,
        ssh_port=22,
    )


def test_firewall_keeps_only_inbound_and_service_ports():
    node = _node()
    assert protected_ports(node) == {22, 80, 21096}
    assert 2096 not in protected_ports(node)
    assert wanted_ports(node, {443, 2083}) == {22, 80, 443, 2083, 21096}
    current = {22, 80, 443, 8443, 2096, 21096, 9999}
    actions = firewall_plan(node, {443, 2083}, current)
    assert ('allow', 2083) in actions
    assert ('delete', 8443) in actions
    assert ('delete', 2096) in actions
    assert ('delete', 9999) in actions
    assert ('allow', 443) not in actions
    assert all(port not in {22, 80, 21096, 443} for kind, port in actions if kind == 'delete')


def test_script_installs_ufw_when_missing():
    script = _script(_node(), {443})
    assert 'apt-get install -y -qq ufw' in script
    assert 'command -v ufw' in script


def test_firewall_opens_missing_service_port():
    node = _node()
    actions = firewall_plan(node, {443}, {443, 8443})
    assert ('allow', 22) in actions
    assert ('allow', 80) in actions
    assert ('allow', 2096) not in actions
    assert ('allow', 21096) in actions
    assert ('delete', 8443) in actions
