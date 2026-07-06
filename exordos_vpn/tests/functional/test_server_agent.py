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

import os
import types

import netaddr
import pytest

from exordos_vpn.common import firewall_kinds
from exordos_vpn.dm import models
from exordos_vpn.services import server_agent
from exordos_vpn.tests.functional import base

CHAIN_PREFIX = "exordos_vpn"
SUBNET_CIDR = "10.8.0.1/24"
ROUTING_PROTO_ID = 172


def _chain_name():
    return server_agent._make_chain_name(
        CHAIN_PREFIX, "", netaddr.IPNetwork(SUBNET_CIDR).cidr
    )


class TestServerAgentFirewall(base.DbTestCase):
    """Functional tests for AgentService._reconcile_firewall().

    These run real iptables commands inside an isolated, unprivileged
    network namespace (see the `iptables_netns` fixture), so they catch
    real reconciliation bugs (e.g. rule-string mismatches, duplicate
    inserts, chains that get recreated every cycle) that a fake/mocked
    iptables backend would not.
    """

    def _make_conf(self, tmp_path, **overrides):
        conf = types.SimpleNamespace(
            openvpn_config_dir=str(tmp_path),
            openvpn_subnet_cidr=SUBNET_CIDR,
            firewall_enabled=True,
            firewall_chain_prefix=CHAIN_PREFIX,
            firewall_global_whitelist="",
            routing_enabled=False,
            routing_proto_id=ROUTING_PROTO_ID,
            dns_resolve_min_interval_seconds=30,
            dns_resolvers="",
            private_networks="",
        )
        for key, value in overrides.items():
            setattr(conf, key, value)
        return conf

    def _make_network(self, cidr="10.8.0.0/24"):
        network = models.Network(name="testnet", subnets=[netaddr.IPNetwork(cidr)])
        network.insert()
        return network

    def _make_account(self, network, name, offset, **kwargs):
        kwargs.setdefault("status", "ACTIVE")
        kwargs.setdefault("network_access_type", "RESTRICTED")
        account = models.Account(
            account_name=name,
            user_id=f"user-{name}",
            pin="123456",
            network=network,
            address_offset=offset,
            **kwargs,
        )
        account.insert()
        return account

    def _make_service(
        self, name, subnets=None, tags=None, kinds=None, domains=None, nexthop=None
    ):
        service = models.Service(
            name=name,
            subnets=[netaddr.IPNetwork(s) for s in (subnets or [])],
            domains=domains or [],
            tags=tags or [],
            kinds=kinds or [],
            nexthop=netaddr.IPAddress(nexthop) if nexthop else None,
        )
        service.insert()
        return service

    def _read_ccd(self, tmp_path, name, account_name):
        ccd_dir = f"ccd_{name}" if name else "ccd"
        path = os.path.join(str(tmp_path), ccd_dir, account_name)
        with open(path) as f:
            return f.read()

    def _make_department(self, name, parent=None, tags=None):
        department = models.Department(
            name=name,
            parent=parent.uuid if parent else None,
            network_access_tags=tags or [],
        )
        department.insert()
        return department

    def _link_department(self, account, department):
        link = models.AccountDepartment(account=account, department=department)
        link.insert()
        return link

    def test_idempotent_second_reconcile_is_noop(self, tmp_path, iptables_netns):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_type="ALL")
        self._make_account(
            network,
            "bob",
            3,
            network_access_type="RESTRICTED",
            network_access_tags=["web"],
        )
        self._make_service(
            "web-svc",
            ["172.16.0.0/24"],
            tags=["web"],
            kinds=[firewall_kinds.FirewallKindTcp(min_port=443, max_port=443)],
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._reconcile_firewall()

        current = agent._get_chain_rules(chain)
        assert current["accept"] == {
            f"-A {chain} -s 10.8.0.0/24 -d 10.8.0.1/32 -j ACCEPT",
            f"-A {chain} -s 10.8.0.2/32 -j ACCEPT",
            f"-A {chain} -s 10.8.0.3/32 -d 172.16.0.0/24 -p tcp -m tcp --dport 443 -j ACCEPT",
        }
        assert current["drop"] == f"-A {chain} -s 10.8.0.0/24 -j DROP"
        # No duplicate rules: raw line count == 1 chain decl + 3 accept + 1 drop.
        assert len(iptables_netns.get_chain_rules(chain)) == 5
        assert agent._forward_ref_exists("10.8.0.0/24", chain)

        iptables_netns.reset_calls()
        agent._reconcile_firewall()

        assert iptables_netns.mutating_calls() == []
        assert len(iptables_netns.get_chain_rules(chain)) == 5

    def test_new_account_adds_single_rule_without_rebuild(
        self, tmp_path, iptables_netns
    ):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_type="ALL")

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._reconcile_firewall()
        assert len(agent._get_chain_rules(chain)["accept"]) == 2  # server + alice

        self._make_account(network, "carol", 4, network_access_type="ALL")
        iptables_netns.reset_calls()
        agent._reconcile_firewall()

        mutations = iptables_netns.mutating_calls()
        assert len(mutations) == 1
        assert mutations[0][:5] == [
            server_agent.IPTABLES_BIN_PATH,
            "-t",
            "filter",
            "-I",
            chain,
        ]

        current = agent._get_chain_rules(chain)
        assert current["accept"] == {
            f"-A {chain} -s 10.8.0.0/24 -d 10.8.0.1/32 -j ACCEPT",
            f"-A {chain} -s 10.8.0.2/32 -j ACCEPT",
            f"-A {chain} -s 10.8.0.4/32 -j ACCEPT",
        }

    def test_disabled_account_removes_only_its_rule(self, tmp_path, iptables_netns):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_type="ALL")
        bob = self._make_account(network, "bob", 3, network_access_type="ALL")

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._reconcile_firewall()
        assert len(agent._get_chain_rules(chain)["accept"]) == 3  # server + alice + bob

        bob.disable()
        iptables_netns.reset_calls()
        agent._reconcile_firewall()

        mutations = iptables_netns.mutating_calls()
        assert len(mutations) == 1
        assert mutations[0][:5] == [
            server_agent.IPTABLES_BIN_PATH,
            "-t",
            "filter",
            "-D",
            chain,
        ]

        current = agent._get_chain_rules(chain)
        assert current["accept"] == {
            f"-A {chain} -s 10.8.0.0/24 -d 10.8.0.1/32 -j ACCEPT",
            f"-A {chain} -s 10.8.0.2/32 -j ACCEPT",
        }

    def test_disabling_firewall_removes_stale_chain_idempotently(
        self, tmp_path, iptables_netns
    ):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_type="ALL")

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._reconcile_firewall()
        assert chain in agent._list_managed_chains({CHAIN_PREFIX})

        conf.firewall_enabled = False
        iptables_netns.reset_calls()
        agent._reconcile_firewall()

        assert chain not in agent._list_managed_chains({CHAIN_PREFIX})
        assert not agent._forward_ref_exists("10.8.0.0/24", chain)

        # Removal itself must be idempotent: nothing left to do on a third pass.
        iptables_netns.reset_calls()
        agent._reconcile_firewall()
        assert iptables_netns.mutating_calls() == []


class TestServerAgentRouting(TestServerAgentFirewall):
    """Functional tests for nexthop routing / DNS-resolved ipsets.

    Reuses TestServerAgentFirewall's fixtures/helpers (_make_network,
    _make_account, _make_service, _make_conf) since routing is just a new
    facet of the same Service model. Runs against the real `ip`/`ipset`
    binaries inside the isolated netns (see `iptables_netns`).
    """

    def test_static_nexthop_route_added_and_removed(self, tmp_path, iptables_netns):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        service = self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, routing_enabled=True)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        agent._reconcile_routing()

        routes = agent._get_current_routes(ROUTING_PROTO_ID)
        assert routes == {"93.184.216.0/24": "127.0.0.2"}

        # Idempotent: second pass issues no mutating ip/ipset calls.
        iptables_netns.reset_calls()
        agent._reconcile_routing()
        assert iptables_netns.mutating_calls() == []

        # Clearing nexthop removes the route.
        service.nexthop = None
        service.save()
        agent._reconcile_routing()
        assert agent._get_current_routes(ROUTING_PROTO_ID) == {}

    def test_not_on_link_nexthop_is_skipped(self, tmp_path, iptables_netns):
        """A nexthop that isn't directly reachable can't be used as a
        gateway (`ip route replace ... via` would fail); its service is
        skipped with a warning while other services still get routes."""
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service(
            "bad-svc", ["198.51.100.0/24"], tags=["ext"], nexthop="203.0.113.99"
        )
        self._make_service(
            "good-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, routing_enabled=True)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        agent._reconcile_routing()

        assert agent._get_current_routes(ROUTING_PROTO_ID) == {
            "93.184.216.0/24": "127.0.0.2"
        }

    def test_routing_disabled_does_not_install_routes(self, tmp_path, iptables_netns):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, routing_enabled=False)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        agent._reconcile_routing()

        assert agent._get_current_routes(ROUTING_PROTO_ID) == {}

    def test_disabled_account_does_not_remove_nexthop_route(
        self, tmp_path, iptables_netns
    ):
        """Routing is destination-only: an account losing ACL access must
        not affect the (shared) route for that destination."""
        network = self._make_network()
        bob = self._make_account(network, "bob", 3, network_access_tags=["ext"])
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, routing_enabled=True)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._reconcile_routing()
        agent._reconcile_firewall()
        assert agent._get_current_routes(ROUTING_PROTO_ID) == {
            "93.184.216.0/24": "127.0.0.2"
        }
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )

        bob.disable()
        agent._reconcile_routing()
        agent._reconcile_firewall()

        # Route survives even though bob can no longer reach that dst.
        assert agent._get_current_routes(ROUTING_PROTO_ID) == {
            "93.184.216.0/24": "127.0.0.2"
        }
        assert not any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )

    def test_domain_service_populates_ipset_and_route(
        self, tmp_path, iptables_netns, monkeypatch
    ):
        monkeypatch.setattr(
            server_agent,
            "_resolve_domain",
            lambda domain, resolvers=None, timeout=5.0: ({"93.184.216.34"}, 300),
        )

        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        service = self._make_service(
            "ext-svc", domains=["example.com"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, routing_enabled=True)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._reconcile_routing()
        agent._reconcile_firewall()

        ipset_name = server_agent._ipset_name(service)
        assert iptables_netns.get_ipset_members(ipset_name) == {"93.184.216.34"}
        assert agent._get_current_routes(ROUTING_PROTO_ID) == {
            "93.184.216.34/32": "127.0.0.2"
        }
        assert any(
            f"--match-set {ipset_name} dst" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )

    def test_domain_ipset_membership_tracks_dns_changes(
        self, tmp_path, iptables_netns, monkeypatch
    ):
        resolved = {"93.184.216.34"}
        monkeypatch.setattr(
            server_agent,
            "_resolve_domain",
            lambda domain, resolvers=None, timeout=5.0: (
                resolved,
                0,
            ),  # ttl=0: re-resolve every tick
        )

        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        service = self._make_service(
            "ext-svc", domains=["example.com"], tags=["ext"], nexthop="127.0.0.2"
        )
        ipset_name = server_agent._ipset_name(service)

        conf = self._make_conf(
            tmp_path, routing_enabled=True, dns_resolve_min_interval_seconds=0
        )
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        agent._reconcile_routing()
        assert iptables_netns.get_ipset_members(ipset_name) == {"93.184.216.34"}
        assert agent._get_current_routes(ROUTING_PROTO_ID) == {
            "93.184.216.34/32": "127.0.0.2"
        }

        resolved = {"93.184.216.99"}
        agent._reconcile_routing()

        assert iptables_netns.get_ipset_members(ipset_name) == {"93.184.216.99"}
        assert agent._get_current_routes(ROUTING_PROTO_ID) == {
            "93.184.216.99/32": "127.0.0.2"
        }

    def test_dns_resolvers_config_is_passed_to_resolver(
        self, tmp_path, iptables_netns, monkeypatch
    ):
        seen_resolvers = []

        def fake_resolve_domain(domain, resolvers=None, timeout=5.0):
            seen_resolvers.append(resolvers)
            return {"93.184.216.34"}, 300

        monkeypatch.setattr(server_agent, "_resolve_domain", fake_resolve_domain)

        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service("ext-svc", domains=["example.com"], tags=["ext"])

        conf = self._make_conf(tmp_path, dns_resolvers="9.9.9.9, 1.1.1.1")
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        agent._reconcile_routing()

        assert seen_resolvers == [["9.9.9.9", "1.1.1.1"]]


class TestServerAgentRoutingFailures(TestServerAgentFirewall):
    """Failure-path coverage for the ipset/ip command wrappers.

    The happy paths above only ever exercise commands that succeed;
    these check that a failing `ipset`/`ip` invocation surfaces as a
    RuntimeError (not silently ignored) and that the one place a
    failure IS expected/swallowed (destroying an ipset still
    referenced by an iptables rule, so it'll be retried next
    iteration) actually behaves that way.
    """

    def test_run_ipset_raises_on_failure(self, tmp_path, iptables_netns):
        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        with pytest.raises(RuntimeError, match="ipset failed"):
            agent._run_ipset("destroy", "exvpn_svc_does_not_exist")

    def test_run_ip_raises_on_failure(self, tmp_path, iptables_netns):
        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        with pytest.raises(RuntimeError, match="ip command failed"):
            agent._run_ip("route", "del", "10.255.255.255/32", "proto", "173")

    def test_routing_failure_does_not_block_firewall_and_ccd(
        self, tmp_path, iptables_netns, monkeypatch
    ):
        """A persistent ipset/route failure must degrade to stale routing,
        not abort the iteration — firewall reconciliation (including
        access revocations) and CCD generation still have to run."""
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, routing_enabled=True)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})

        def boom(*args, **kwargs):
            raise RuntimeError("ipset exploded")

        monkeypatch.setattr(agent, "_reconcile_ipsets", boom)

        agent._iteration()

        chain = _chain_name()
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )
        ccd = os.path.join(str(tmp_path), "ccd", "alice")
        with open(ccd) as f:
            assert 'push "route 93.184.216.0 255.255.255.0"' in f.read()

    def test_stale_ipset_still_in_use_is_retried_next_iteration(
        self, tmp_path, iptables_netns, monkeypatch
    ):
        monkeypatch.setattr(
            server_agent,
            "_resolve_domain",
            lambda domain, resolvers=None, timeout=5.0: ({"93.184.216.34"}, 300),
        )

        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        service = self._make_service(
            "ext-svc", domains=["example.com"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, routing_enabled=True)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        ipset_name = server_agent._ipset_name(service)

        # Populate the ipset and reference it from an iptables ACCEPT rule.
        agent._reconcile_routing()
        agent._reconcile_firewall()
        assert ipset_name in agent._list_managed_ipsets()

        # Service loses its domains (turning subnet-only, to stay valid):
        # the ipset becomes stale, but it's still referenced by the
        # (not-yet-reconciled) firewall chain, so the kernel refuses to
        # destroy it. That failure must be caught and logged, not raised,
        # and the ipset must survive intact.
        service.subnets = [netaddr.IPNetwork("93.184.216.0/24")]
        service.domains = []
        service.save()
        agent._reconcile_routing()

        assert ipset_name in agent._list_managed_ipsets()

        # Once the firewall chain is reconciled too, the ipset is no
        # longer referenced, so the next pass can actually destroy it.
        agent._reconcile_firewall()
        agent._reconcile_routing()

        assert ipset_name not in agent._list_managed_ipsets()


class TestServerAgentCcdRoutePush(TestServerAgentFirewall):
    """Functional tests for split-tunnel CCD `push route`/DNS generation.

    Without a route pushed to the client's OS, a firewall ACCEPT rule is
    moot: matching traffic never enters the tun interface in the first
    place. These run the full `_iteration()` (not just the sub-reconcile
    methods) since the CCD-rebuild gating logic spans firewall/DNS/account
    change detection.
    """

    def test_ccd_pushes_route_for_matched_nexthop_service(
        self, tmp_path, iptables_netns
    ):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route 93.184.216.0 255.255.255.0"' in content

    def test_ccd_no_route_push_for_service_inside_private_networks(
        self, tmp_path, iptables_netns
    ):
        """A service whose subnets are contained in `private_networks`
        needs no per-account route lines: the OpenVPN server config
        already pushes a covering route to every client."""
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["internal"])
        self._make_service("internal-svc", ["172.16.5.0/24"], tags=["internal"])

        conf = self._make_conf(tmp_path, private_networks="172.16.0.0/12")
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route' not in content

    def test_ccd_pushes_route_for_external_service_without_nexthop(
        self, tmp_path, iptables_netns
    ):
        """The push criterion is "outside private_networks", not "has a
        nexthop": an external destination reached via the gateway's
        normal default route still needs the client-side route to enter
        the tunnel at all."""
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service("ext-plain-svc", ["93.184.216.0/24"], tags=["ext"])

        conf = self._make_conf(tmp_path, private_networks="172.16.0.0/12")
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route 93.184.216.0 255.255.255.0"' in content

    def test_ccd_private_subnet_of_nexthop_service_not_pushed(
        self, tmp_path, iptables_netns
    ):
        """Even for a nexthop service, subnets inside private_networks are
        already routed into the tunnel by the server-level push — only the
        external part of the service gets per-account lines."""
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service(
            "mixed-svc",
            ["93.184.216.0/24", "172.16.5.0/24"],
            tags=["ext"],
            nexthop="127.0.0.2",
        )

        conf = self._make_conf(tmp_path, private_networks="172.16.0.0/12")
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route 93.184.216.0 255.255.255.0"' in content
        assert 'push "route 172.16.5.0 255.255.255.0"' not in content

    def test_ccd_route_push_for_all_access_type_still_needs_tag(
        self, tmp_path, iptables_netns
    ):
        """ALL accounts are firewall-ACCEPTed everywhere, but route pushes
        are always tag-gated: an ALL account only gets a service's route
        if it also holds that service's tag, same as a RESTRICTED account
        would; private-net destinations stay covered by the server-level
        push regardless."""
        network = self._make_network()
        self._make_account(
            network, "alice", 2, network_access_type="ALL", network_access_tags=["ext"]
        )
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )
        self._make_service(
            "other-svc", ["93.184.217.0/24"], tags=["other"], nexthop="127.0.0.2"
        )
        self._make_service("internal-svc", ["172.16.5.0/24"], tags=["internal"])

        conf = self._make_conf(tmp_path, private_networks="172.16.0.0/12")
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route 93.184.216.0 255.255.255.0"' in content
        assert 'push "route 93.184.217.0 255.255.255.0"' not in content
        assert 'push "route 172.16.5.0 255.255.255.0"' not in content

    def test_ccd_no_route_push_for_unmatched_tags(self, tmp_path, iptables_netns):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["other"])
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route' not in content

    def test_ccd_domain_service_pushes_ip_routes_but_never_dns(
        self, tmp_path, iptables_netns, monkeypatch
    ):
        """Resolved domain IPs get /32 route pushes; DNS itself is NOT
        pushed per-account — clients get their resolver from the OpenVPN
        server config's global `push "dhcp-option DNS"` (they need one
        for everything, not just domain services)."""
        monkeypatch.setattr(
            server_agent,
            "_resolve_domain",
            lambda domain, resolvers=None, timeout=5.0: ({"93.184.216.34"}, 300),
        )

        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service(
            "ext-svc", domains=["example.com"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, dns_resolvers="9.9.9.9")
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route 93.184.216.34 255.255.255.255"' in content
        assert "dhcp-option" not in content
        assert "9.9.9.9" not in content

    def test_ccd_rebuilds_when_service_changes_not_account(
        self, tmp_path, iptables_netns
    ):
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        service = self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()
        assert 'push "route 93.184.216.0 255.255.255.0"' in self._read_ccd(
            tmp_path, "", "alice"
        )

        # Only the service changes; alice's own account row is untouched.
        service.subnets = [netaddr.IPNetwork("93.184.217.0/24")]
        service.save()
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route 93.184.217.0 255.255.255.0"' in content
        assert 'push "route 93.184.216.0 255.255.255.0"' not in content

    def test_ccd_rebuilds_when_dns_resolved_ips_change(
        self, tmp_path, iptables_netns, monkeypatch
    ):
        resolved = {"93.184.216.34"}
        monkeypatch.setattr(
            server_agent,
            "_resolve_domain",
            lambda domain, resolvers=None, timeout=5.0: (resolved, 0),
        )

        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        self._make_service(
            "ext-svc", domains=["example.com"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path, dns_resolve_min_interval_seconds=0)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()
        assert 'push "route 93.184.216.34 255.255.255.255"' in self._read_ccd(
            tmp_path, "", "alice"
        )

        # DNS answer rotates; no Service/Account row changes at all.
        resolved = {"93.184.216.99"}
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert 'push "route 93.184.216.99 255.255.255.255"' in content
        assert 'push "route 93.184.216.34 255.255.255.255"' not in content

    def test_ccd_dedups_route_shared_by_multiple_matched_services(
        self, tmp_path, iptables_netns
    ):
        """Two services can overlap in the subnet they grant (e.g. matched
        via different tags the same account holds) — the pushed route line
        must appear once, not once per matching service."""
        network = self._make_network()
        self._make_account(
            network, "alice", 2, network_access_tags=["internal", "other"]
        )
        self._make_service(
            "svc-a", ["93.184.216.0/24"], tags=["internal"], nexthop="127.0.0.2"
        )
        self._make_service(
            "svc-b", ["93.184.216.0/24"], tags=["other"], nexthop="127.0.0.2"
        )
        self._make_service(
            "svc-c", ["93.184.217.0/24"], tags=["other"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        content = self._read_ccd(tmp_path, "", "alice")
        assert content.count('push "route 93.184.216.0 255.255.255.0"') == 1
        assert 'push "route 93.184.217.0 255.255.255.0"' in content

    def test_service_delete_revokes_firewall_rule_and_ccd_route(
        self, tmp_path, iptables_netns
    ):
        """A deleted Service (unlike an updated one) has no row left to
        match an `updated_at >=` filter — regression test for the gap
        where _has_firewall_data_changed() missed deletions entirely,
        leaving a revoked destination's ACCEPT rule/pushed route in place
        indefinitely for already-matched accounts.
        """
        network = self._make_network()
        self._make_account(network, "alice", 2, network_access_tags=["ext"])
        service = self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._iteration()
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )
        assert 'push "route 93.184.216.0 255.255.255.0"' in self._read_ccd(
            tmp_path, "", "alice"
        )

        service.delete()
        agent._iteration()

        assert not any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )
        assert 'push "route 93.184.216.0 255.255.255.0"' not in self._read_ccd(
            tmp_path, "", "alice"
        )


class TestServerAgentDepartments(TestServerAgentFirewall):
    """Functional tests for department-granted access tags.

    Departments are pure tag carriers: matching stays tag-based, only the
    "effective tags of an account" computation changes. These run the full
    `_iteration()` so the change-detection path (department/membership
    rows, not just accounts/services) is exercised too.
    """

    def test_department_tag_grants_firewall_and_ccd(self, tmp_path, iptables_netns):
        network = self._make_network()
        alice = self._make_account(network, "alice", 2)  # no own tags
        department = self._make_department("engineering", tags=["ext"])
        self._link_department(alice, department)
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        chain = _chain_name()
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )
        assert 'push "route 93.184.216.0 255.255.255.0"' in self._read_ccd(
            tmp_path, "", "alice"
        )

    def test_nested_department_inherits_parent_tags(self, tmp_path, iptables_netns):
        """A tag on a parent department applies to accounts of child
        departments."""
        network = self._make_network()
        alice = self._make_account(network, "alice", 2)
        root = self._make_department("org", tags=["ext"])
        child = self._make_department("backend", parent=root)
        self._link_department(alice, child)
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        chain = _chain_name()
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )
        assert 'push "route 93.184.216.0 255.255.255.0"' in self._read_ccd(
            tmp_path, "", "alice"
        )

    def test_department_tag_change_rebuilds_without_account_touch(
        self, tmp_path, iptables_netns
    ):
        """Changing only the department row (account untouched) must
        re-evaluate both firewall and CCD on the next iteration."""
        network = self._make_network()
        alice = self._make_account(network, "alice", 2)
        department = self._make_department("engineering", tags=["ext"])
        self._link_department(alice, department)
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._iteration()
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )

        department.network_access_tags = ["other"]
        department.save()
        agent._iteration()

        assert not any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )
        assert 'push "route 93.184.216.0 255.255.255.0"' not in self._read_ccd(
            tmp_path, "", "alice"
        )

    def test_membership_removal_revokes_access(self, tmp_path, iptables_netns):
        """Deleting a membership link leaves no row for an `updated_at >=`
        filter to match — regression test for count-based detection of
        AccountDepartment deletions."""
        network = self._make_network()
        alice = self._make_account(network, "alice", 2)
        department = self._make_department("engineering", tags=["ext"])
        link = self._link_department(alice, department)
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._iteration()
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )

        link.delete()
        agent._iteration()

        assert not any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )
        assert 'push "route 93.184.216.0 255.255.255.0"' not in self._read_ccd(
            tmp_path, "", "alice"
        )

    def test_department_delete_revokes_access(self, tmp_path, iptables_netns):
        """Deleting a department cascades its membership rows (SQL FK) and
        must revoke access on the next iteration."""
        network = self._make_network()
        alice = self._make_account(network, "alice", 2)
        department = self._make_department("engineering", tags=["ext"])
        self._link_department(alice, department)
        self._make_service(
            "ext-svc", ["93.184.216.0/24"], tags=["ext"], nexthop="127.0.0.2"
        )

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        chain = _chain_name()

        agent._iteration()
        assert any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )

        department.delete()
        agent._iteration()

        assert not any(
            "93.184.216.0/24" in rule
            for rule in agent._get_chain_rules(chain)["accept"]
        )

    def test_own_tags_union_with_department_tags(self, tmp_path, iptables_netns):
        """Personal account tags stay as an additive exception mechanism."""
        network = self._make_network()
        alice = self._make_account(network, "alice", 2, network_access_tags=["own"])
        department = self._make_department("engineering", tags=["ext"])
        self._link_department(alice, department)
        self._make_service("ext-svc", ["93.184.216.0/24"], tags=["ext"])
        self._make_service("own-svc", ["93.184.217.0/24"], tags=["own"])

        conf = self._make_conf(tmp_path)
        agent = server_agent.AgentService(iter_min_period=4, prefixes={"": conf})
        agent._iteration()

        accept = agent._get_chain_rules(_chain_name())["accept"]
        assert any("93.184.216.0/24" in rule for rule in accept)
        assert any("93.184.217.0/24" in rule for rule in accept)
