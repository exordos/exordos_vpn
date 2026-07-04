#    Copyright 2025-2026 Genesis Corporation.
#
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import dns.resolver
import netaddr

from exordos_vpn.services import server_agent


def test_parse_dns_resolvers_valid():
    assert server_agent._parse_dns_resolvers("1.1.1.1, 8.8.8.8") == [
        "1.1.1.1",
        "8.8.8.8",
    ]


def test_parse_dns_resolvers_skips_invalid_entries():
    assert server_agent._parse_dns_resolvers("1.1.1.1,not-an-ip,,8.8.8.8") == [
        "1.1.1.1",
        "8.8.8.8",
    ]


def test_parse_dns_resolvers_empty():
    assert server_agent._parse_dns_resolvers("") == []
    assert server_agent._parse_dns_resolvers(None) == []


def test_parse_private_networks():
    assert server_agent._parse_private_networks(
        "10.0.0.0/8, 172.16.0.0/12,not-a-net,,192.168.1.1"
    ) == [
        netaddr.IPNetwork("10.0.0.0/8"),
        netaddr.IPNetwork("172.16.0.0/12"),
        netaddr.IPNetwork("192.168.1.1/32"),
    ]
    assert server_agent._parse_private_networks("") == []
    assert server_agent._parse_private_networks(None) == []


def test_in_private_networks():
    private = server_agent._parse_private_networks("10.0.0.0/8,172.16.0.0/12")
    assert server_agent._in_private_networks(netaddr.IPNetwork("10.5.0.0/24"), private)
    assert server_agent._in_private_networks(netaddr.IPAddress("172.16.0.53"), private)
    assert not server_agent._in_private_networks(
        netaddr.IPNetwork("93.184.216.0/24"), private
    )
    # A subnet merely overlapping (not contained in) a private network is
    # still pushed — conservative: better a redundant route than none.
    assert not server_agent._in_private_networks(
        netaddr.IPNetwork("10.0.0.0/7"), private
    )
    assert not server_agent._in_private_networks(
        netaddr.IPNetwork("93.184.216.0/24"), []
    )


class _FakeAnswer:
    """Mimics the bits of dns.resolver.Answer that _resolve_domain reads."""

    def __init__(self, ips, ttl):
        self._ips = ips
        self.rrset = self
        self.ttl = ttl

    def __iter__(self):
        return iter(self._ips)


def test_resolve_domain_uses_configured_resolvers(monkeypatch):
    seen = {}

    class FakeResolver:
        def __init__(self, configure):
            seen["configure"] = configure

        def resolve(self, domain, rdtype, lifetime):
            seen["nameservers"] = self.nameservers
            seen["domain"] = domain
            return _FakeAnswer(["93.184.216.34"], ttl=300)

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)

    result = server_agent._resolve_domain("example.com", resolvers=["9.9.9.9"])

    assert seen["configure"] is False
    assert seen["nameservers"] == ["9.9.9.9"]
    assert result == ({"93.184.216.34"}, 300)


def test_resolve_domain_uses_system_resolver_when_no_resolvers_given(monkeypatch):
    used_default = {}

    def fake_get_default_resolver():
        used_default["called"] = True

        class FakeResolver:
            def resolve(self, domain, rdtype, lifetime):
                return _FakeAnswer(["93.184.216.34"], ttl=60)

        return FakeResolver()

    monkeypatch.setattr(dns.resolver, "get_default_resolver", fake_get_default_resolver)

    result = server_agent._resolve_domain("example.com")

    assert used_default["called"] is True
    assert result == ({"93.184.216.34"}, 60)
