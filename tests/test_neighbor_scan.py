import ipaddress

import pytest

from app.neighbor_scan import classify_hit, hosts_in_slash24, require_global_ipv4


def test_slash24_skips_own_address_and_stays_inside_the_network():
    cidr, hosts = hosts_in_slash24('95.85.120.14')
    assert cidr == '95.85.120.0/24'
    assert '95.85.120.14' not in hosts
    assert '95.85.120.0' not in hosts
    assert '95.85.120.255' not in hosts
    assert len(hosts) == 253
    assert all(ipaddress.ip_address(ip) in ipaddress.ip_network(cidr) for ip in hosts)


def test_private_and_ipv6_addresses_are_refused():
    with pytest.raises(ValueError):
        require_global_ipv4('10.0.0.8')
    with pytest.raises(ValueError):
        require_global_ipv4('2001:db8::1')


def test_matching_dns_is_kept_and_stolen_cert_is_dropped():
    kept = classify_hit(
        '95.85.120.40',
        tls13=True,
        h2=True,
        domain='shop.nordmail.fi',
        wildcard_only=False,
        issuer="Let's Encrypt",
        resolved=['95.85.120.40'],
    )
    stolen = classify_hit(
        '95.85.120.21',
        tls13=True,
        h2=True,
        domain='www.google.com',
        wildcard_only=False,
        issuer='Google Trust Services',
        resolved=['142.251.1.119'],
    )
    assert kept['keep'] is True
    assert kept['dns'] == 'совпал'
    assert stolen['keep'] is False
    assert stolen['dns'] == 'чужой IP'


def test_wildcard_weak_tls_and_dns_failure_are_not_kept():
    wildcard = classify_hit(
        '95.85.120.19',
        tls13=True,
        h2=True,
        domain='',
        wildcard_only=True,
        issuer='GlobalSign',
        resolved=None,
    )
    weak = classify_hit(
        '95.85.120.9',
        tls13=False,
        h2=False,
        domain='old.example',
        wildcard_only=False,
        issuer="Let's Encrypt",
        resolved=['95.85.120.9'],
    )
    unresolved = classify_hit(
        '95.85.120.50',
        tls13=True,
        h2=True,
        domain='gone.example',
        wildcard_only=False,
        issuer="Let's Encrypt",
        resolved=None,
    )
    assert wildcard['dns'] == 'маска'
    assert weak['dns'] == 'слабый TLS'
    assert unresolved['dns'] == 'нет DNS'
    assert not any(row['keep'] for row in (wildcard, weak, unresolved))
