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
from exordos_vpn.services import scheduler

DOMAIN = "scheduler"

scheduler_config_opts = [
    cfg.IntOpt(
        "clean-unused-offsets-days",
        default=7,
        help="Remove address offset from disabled certs updated later than X days",
    ),
]

CONF = cfg.CONF
CONF.register_cli_opts(scheduler_config_opts, DOMAIN)
ra_config_opts.register_posgresql_db_opts(CONF)


def main():
    config.parse(sys.argv[1:])

    infra_log.configure()
    log = logging.getLogger(__name__)

    engines.engine_factory.configure_postgresql_factory(CONF)

    service = scheduler.SchedulerService(
        iter_min_period=10,
        offset_days=CONF[DOMAIN].clean_unused_offsets_days,
    )

    service.start()

    log.info("Bye!!!")


if __name__ == "__main__":
    main()
