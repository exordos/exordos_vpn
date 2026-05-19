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
import logging
import os
import netaddr

from gcl_looper.services import basic
from restalchemy.common import contexts
from restalchemy.dm import filters as dm_filters
from restalchemy.dm import types

from exordos_vpn.dm import models


LOG = logging.getLogger(__name__)


class AgentService(basic.BasicService):
    def __init__(self, prefixes=None, **kwargs):
        self.prefixes = prefixes
        self._ctx = contexts.Context()
        self.last_processed_at = datetime.datetime.strptime(
            "2000-01-01T00:00:00.000000Z", types.OPENAPI_DATETIME_FMT
        )
        # lag to avoid race conditions
        self.lag = datetime.timedelta(seconds=30)
        super().__init__(**kwargs)

    def _iteration(self):
        iter_started = datetime.datetime.now(datetime.timezone.utc)
        with self._ctx.session_manager() as s:
            filters = {
                "updated_at": dm_filters.GE(self.last_processed_at),
            }
            accounts = models.Account.objects.get_all(session=s, filters=filters)

        for name, conf in self.prefixes.items():
            self.process_instance(name, conf, accounts)

        # TODO: sort accounts by updated_at and use the last one here
        self.last_processed_at = iter_started - self.lag

    def process_instance(self, name, conf, accounts):
        cidr = netaddr.IPNetwork(conf.openvpn_subnet_cidr)
        dir = conf.openvpn_config_dir
        ccd_dir = os.path.join(dir, f"ccd_{name}" if name else "ccd")
        if not os.path.exists(ccd_dir):
            os.makedirs(ccd_dir)
        for account in accounts:
            LOG.info(f"({name})Processing account: {account.account_name}")
            ccd_file_path = os.path.join(ccd_dir, account.account_name)
            with open(ccd_file_path, "w") as f:
                # If the account is disabled, disable the client in CCD.
                if account.status == "DISABLED":
                    f.write("disable\n")
                    # Disabled account don't need any other settings
                    continue

                # permanent IP address assignment based on the
                # account's address offset.
                if account.address_offset:
                    f.write(
                        f"ifconfig-push "
                        f"{cidr.network + account.address_offset} "
                        f"{cidr.netmask}\n"
                    )
