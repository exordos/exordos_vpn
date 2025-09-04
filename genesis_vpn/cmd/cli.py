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

import decimal
import glob
import logging
import os
from pathlib import Path
import sys

from rich.console import Console
from rich.table import Table

from oslo_config import cfg
from restalchemy.common import config_opts as ra_config_opts
from restalchemy.dm import filters as dm_filters
from restalchemy.storage.sql import engines
from restalchemy.common import contexts

from genesis_vpn.common import config
from genesis_vpn.common import constants as c
from genesis_vpn.common import log as infra_log
from genesis_vpn.common import ovpn_config
from genesis_vpn.common import privatebin
from genesis_vpn.dm import models


CONSOLE = Console()
CONF = cfg.CONF
ra_config_opts.register_posgresql_db_opts(CONF)
config.register_service_config_opts()


def add_parsers(subparsers):
    create_action = subparsers.add_parser("create")
    create_action.add_argument("user_id", type=str.lower)
    create_action.add_argument(
        "cert_name", type=str.lower, nargs="?", default=None
    )
    create_action.add_argument("--disable-pbin", action="store_true")

    list_action = subparsers.add_parser("list")
    list_action.add_argument("--user-id", required=False)

    gen_config_action = subparsers.add_parser("generate_config")
    gen_config_action.add_argument("uuid")
    gen_config_action.add_argument("--disable-pbin", action="store_true")

    disable_action = subparsers.add_parser("disable")
    disable_action.add_argument("uuid")


CONF.register_cli_opt(cfg.SubCommandOpt("action", handler=add_parsers))


def cert_list(session, conf):
    filters = {}
    if conf.user_id:
        filters["user_id"] = dm_filters.EQ(conf.user_id)
    certs = models.Certificate.objects.get_all(
        session=session, filters=filters
    )
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("uuid", style="dim", width=36)
    table.add_column("user_id")
    table.add_column("name", justify="right")
    table.add_column("status", justify="right")
    for cert in certs:
        table.add_row(
            str(cert.uuid),
            cert.user_id,
            cert.name,
            cert.status,
        )

    CONSOLE.print(table)


def cert_create(session, conf):
    kwargs = {}
    kwargs["user_id"] = conf.user_id
    if conf.cert_name:
        kwargs["name"] = conf.cert_name
    cert = models.Certificate(**kwargs)
    cert.save(session=session)
    CONSOLE.print(f"Certificate created with uuid: {cert.uuid}")
    conf.uuid = cert.uuid
    cert_generate_config(session, conf)


def pbin_send(conf, config_file):
    try:
        if not conf.disable_pbin and CONF[c.COMMON_DOMAIN].get(
            "privatebin_endpoint"
        ):
            dl_link = privatebin.send_file(
                CONF[c.COMMON_DOMAIN].privatebin_endpoint,
                text="Download your config file (see attachment)",
                file=config_file,
            )
            CONSOLE.print(
                f"One-time download link, lasts 1 week: {dl_link['full_url']}"
            )
    except Exception as e:
        print(
            f"Upload to pbin failed, feel free to retry with `generate_config`, error: {e}"
        )


def cert_generate_config(session, conf):
    filters = {}
    filters["uuid"] = dm_filters.EQ(conf.uuid)
    cert = models.Certificate.objects.get_one(session=session, filters=filters)

    if not os.path.exists(CONF[c.COMMON_DOMAIN].openvpn_client_configs_dir):
        os.makedirs(CONF[c.COMMON_DOMAIN].openvpn_client_configs_dir)

    config_file = os.path.join(
        CONF[c.COMMON_DOMAIN].openvpn_client_configs_dir,
        ovpn_config.generate_ovpn_config_name(cert),
    )
    with open(config_file, "w") as f:
        f.write(ovpn_config.generate_ovpn_config(cert))

    CONSOLE.print(f"Configuration file generated at {config_file}")
    pbin_send(conf, config_file)


def cert_disable(session, conf):
    filters = {}
    filters["uuid"] = dm_filters.EQ(conf.uuid)
    cert = models.Certificate.objects.get_one(session=session, filters=filters)
    cert.disable(session=session)

    CONSOLE.print(f"Certificate {cert.uuid} disabled")


FUNC_MAPPING = {
    "list": cert_list,
    "create": cert_create,
    "disable": cert_disable,
    "generate_config": cert_generate_config,
}


def main():
    # Parse config
    config.parse(sys.argv[1:])

    # Configure logging
    infra_log.configure()
    log = logging.getLogger(__name__)
    engines.engine_factory.configure_postgresql_factory(CONF)

    ctx = contexts.Context()
    with ctx.session_manager() as s:
        FUNC_MAPPING[CONF.action.name](s, CONF.action)


if __name__ == "__main__":
    main()
