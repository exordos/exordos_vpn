#    Copyright 2025 Genesis Corporation.
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

import logging
import sys

from oslo_config import cfg
from restalchemy.common import config_opts as ra_config_opts
from restalchemy.storage.sql import engines

from exordos_vpn.common import config
from exordos_vpn.common import log as infra_log
from exordos_vpn.services import server_agent

DOMAIN = "server_agent"


CONF = cfg.CONF
ra_config_opts.register_posgresql_db_opts(CONF)

SECTION_PREFIX = "server_agent"

agent_config_opts = [
    cfg.StrOpt(
        "openvpn_config_dir",
        help="Path to openvpn config files",
        required=True,
        default="/etc/openvpn",
    ),
    cfg.StrOpt(
        "openvpn_subnet_cidr",
        help="Openvpn subnet cidr, in 0.0.0.0/0 format",
        required=True,
    ),
    cfg.BoolOpt(
        "firewall_enabled",
        default=True,
        help="Enable iptables-based network access control",
    ),
    cfg.StrOpt(
        "firewall_chain_prefix",
        default="exordos_vpn",
        help="Prefix for iptables chain names",
    ),
    cfg.StrOpt(
        "firewall_global_whitelist",
        default="",
        help="Comma-separated list of CIDR blocks globally allowed "
        "for all VPN clients (e.g. 8.8.8.8/32,1.1.1.1/32,10.0.0.0/8)",
    ),
    cfg.BoolOpt(
        "routing_enabled",
        default=False,
        help="Enable nexthop-based routing for tagged external resources "
        "(services with a nexthop set)",
    ),
    cfg.IntOpt(
        "routing_proto_id",
        default=172,
        help="rtnetlink 'proto' value used to tag routes owned by this "
        "agent, so route reconciliation never touches unrelated host routes",
    ),
    cfg.IntOpt(
        "dns_resolve_min_interval_seconds",
        default=30,
        help="Floor between re-resolutions of a domain's A/AAAA records, "
        "regardless of the DNS response TTL",
    ),
    cfg.StrOpt(
        "dns_resolvers",
        default="",
        help="Comma-separated list of DNS server IPs to use for resolving "
        "Service.domains (e.g. 1.1.1.1,8.8.8.8); empty uses the system "
        "resolver (/etc/resolv.conf). For domain-based routing the "
        "clients must resolve to the same IPs, so point the OpenVPN "
        "server config's global 'push \"dhcp-option DNS ...\"' at the "
        "same resolver",
    ),
    cfg.StrOpt(
        "private_networks",
        default="",
        help="Comma-separated CIDR blocks of the private networks the "
        "OpenVPN server config already pushes to every client "
        "(e.g. 10.0.0.0/8,172.16.0.0/12); service destinations inside "
        "them are skipped when generating per-account CCD route pushes",
    ),
]


def main():
    config.parse(sys.argv[1:])

    infra_log.configure()
    log = logging.getLogger(__name__)

    engines.engine_factory.configure_postgresql_factory(CONF)

    prefixes = {}
    for section in CONF.list_all_sections():
        if not section.startswith(SECTION_PREFIX):
            continue
        name = section.split("_", 2)[2:]

        name = name[0] if name else ""

        CONF.register_opts(agent_config_opts, section)

        prefixes[name] = CONF[section]

    CONF.reload_config_files()
    CONF._check_required_opts()

    if not prefixes:
        print("No agent config found! Exiting. Please check your configuration file.")
        return 1

    service = server_agent.AgentService(
        iter_min_period=4,
        prefixes=prefixes,
    )

    service.start()

    log.info("Bye!!!")


if __name__ == "__main__":
    main()
