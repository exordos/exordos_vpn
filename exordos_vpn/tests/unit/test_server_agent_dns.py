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

import datetime

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


class _FakeService:
    def __init__(self, domains):
        self.domains = domains


def _bare_agent():
    """An AgentService with only the state _reconcile_dns touches, so these
    stay unit tests (no DB, no config, no openvpn dirs)."""
    agent = server_agent.AgentService.__new__(server_agent.AgentService)
    agent._dns_cache = {}
    return agent


def _expire_wait(agent, domain):
    """Pretend the wait before the next attempt elapsed, without sleeping."""
    agent._dns_cache[domain].next_attempt_at = datetime.datetime.now(
        datetime.timezone.utc
    ) - datetime.timedelta(seconds=1)


class TestReconcileDnsBackoff:
    """A domain that never resolves (typo, or added before its records exist)
    must not be re-queried on every tick: _iteration() resolves before it
    reconciles the firewall, so a resolver that times out on such a domain
    would delay access revocations by the resolver timeout, every tick.
    """

    DEAD = "norecords.example.com"
    LIVE = "good.example.com"

    def _resolver(self, calls):
        def fake_resolve(domain, resolvers=None, timeout=5.0):
            calls.append(domain)
            if domain == self.LIVE:
                return {"1.2.3.4"}, 60
            raise dns.resolver.NoAnswer()

        return fake_resolve

    def test_failure_is_queried_once_then_backed_off(self, monkeypatch):
        calls = []
        monkeypatch.setattr(server_agent, "_resolve_domain", self._resolver(calls))
        agent = _bare_agent()
        services = [_FakeService([self.DEAD])]

        for _ in range(5):
            resolved = agent._reconcile_dns(services, min_interval_seconds=30)

        # One query total, not one per tick; the domain resolves to nothing,
        # so it never gains routes/ipset entries.
        assert calls == [self.DEAD]
        assert resolved == {self.DEAD: set()}

    def test_backoff_doubles_up_to_one_hour(self, monkeypatch):
        calls = []
        monkeypatch.setattr(server_agent, "_resolve_domain", self._resolver(calls))
        agent = _bare_agent()
        services = [_FakeService([self.DEAD])]

        delays = []
        for _ in range(10):
            agent._reconcile_dns(services, min_interval_seconds=30)
            delays.append(agent._dns_cache[self.DEAD].backoff)
            _expire_wait(agent, self.DEAD)

        assert delays[:4] == [30, 60, 120, 240]
        assert delays[-1] == server_agent.DNS_FAILURE_BACKOFF_MAX_SECONDS
        assert max(delays) == server_agent.DNS_FAILURE_BACKOFF_MAX_SECONDS

    def test_backoff_does_not_block_healthy_domains(self, monkeypatch):
        calls = []
        monkeypatch.setattr(server_agent, "_resolve_domain", self._resolver(calls))
        agent = _bare_agent()
        services = [_FakeService([self.DEAD, self.LIVE])]

        for _ in range(3):
            resolved = agent._reconcile_dns(services, min_interval_seconds=30)

        assert resolved == {self.LIVE: {"1.2.3.4"}, self.DEAD: set()}
        assert calls.count(self.LIVE) == 1  # TTL-cached
        assert calls.count(self.DEAD) == 1  # backed off

    def test_last_known_good_still_served_while_backed_off(self, monkeypatch):
        """Backoff must never withdraw access: a domain that resolved before
        and fails now keeps serving its last-known-good IPs.
        """
        answers = {"ips": ({"1.2.3.4"}, 0)}

        def fake_resolve(domain, resolvers=None, timeout=5.0):
            if answers["ips"] is None:
                raise dns.resolver.NoAnswer()
            return answers["ips"]

        monkeypatch.setattr(server_agent, "_resolve_domain", fake_resolve)
        agent = _bare_agent()
        services = [_FakeService([self.LIVE])]

        # ttl=0 with min_interval=0 means the entry is stale on the next tick.
        assert agent._reconcile_dns(services, min_interval_seconds=0) == {
            self.LIVE: {"1.2.3.4"}
        }

        answers["ips"] = None
        for _ in range(3):
            resolved = agent._reconcile_dns(services, min_interval_seconds=0)
            assert resolved == {self.LIVE: {"1.2.3.4"}}
            _expire_wait(agent, self.LIVE)

    def test_success_resets_backoff(self, monkeypatch):
        answers = {"ips": None}

        def fake_resolve(domain, resolvers=None, timeout=5.0):
            if answers["ips"] is None:
                raise dns.resolver.NoAnswer()
            return answers["ips"]

        monkeypatch.setattr(server_agent, "_resolve_domain", fake_resolve)
        agent = _bare_agent()
        services = [_FakeService([self.LIVE])]

        for _ in range(3):
            agent._reconcile_dns(services, min_interval_seconds=30)
            _expire_wait(agent, self.LIVE)
        assert agent._dns_cache[self.LIVE].backoff == 120

        answers["ips"] = ({"1.2.3.4"}, 60)
        resolved = agent._reconcile_dns(services, min_interval_seconds=30)

        assert resolved == {self.LIVE: {"1.2.3.4"}}
        # Backoff cleared, so a later failure starts from the floor again.
        assert agent._dns_cache[self.LIVE].backoff == 0

    def test_failure_state_dropped_when_domain_leaves_services(self, monkeypatch):
        calls = []
        monkeypatch.setattr(server_agent, "_resolve_domain", self._resolver(calls))
        agent = _bare_agent()

        agent._reconcile_dns([_FakeService([self.DEAD])], min_interval_seconds=30)
        assert self.DEAD in agent._dns_cache

        # Domain removed from every Service: no stale state left behind, and
        # re-adding it gets a fresh immediate attempt rather than an hour wait.
        agent._reconcile_dns([_FakeService([])], min_interval_seconds=30)
        assert agent._dns_cache == {}

        agent._reconcile_dns([_FakeService([self.DEAD])], min_interval_seconds=30)
        assert calls == [self.DEAD, self.DEAD]
