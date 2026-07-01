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

import types

import netaddr

from exordos_vpn.common import firewall_kinds
from exordos_vpn.dm import models
from exordos_vpn.services import server_agent
from exordos_vpn.tests.functional import base

CHAIN_PREFIX = "exordos_vpn"
SUBNET_CIDR = "10.8.0.1/24"


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

    def _make_service(self, name, subnets, tags=None, kinds=None):
        service = models.Service(
            name=name,
            subnets=[netaddr.IPNetwork(s) for s in subnets],
            tags=tags or [],
            kinds=kinds or [],
        )
        service.insert()
        return service

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
