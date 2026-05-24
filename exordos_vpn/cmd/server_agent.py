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
