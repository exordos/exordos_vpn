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

import decimal
import glob
import logging
import os
from pathlib import Path
import secrets
import string
import sys

from oslo_config import cfg
from restalchemy.common import config_opts as ra_config_opts
from restalchemy.common import contexts
from restalchemy.storage.sql import engines

from exordos_vpn.common import cert
from exordos_vpn.common import config
from exordos_vpn.common import log as infra_log
from exordos_vpn.dm import models

cli_opts = [
    cfg.StrOpt("easyrsa-dir", help="Path to easyrsa dir to import from", required=True),
]

CONF = cfg.CONF
ra_config_opts.register_posgresql_db_opts(CONF)
config.register_service_config_opts()
CONF.register_cli_opts(cli_opts)


def main():
    # Parse config
    config.parse(sys.argv[1:])

    # Configure logging
    infra_log.configure()
    log = logging.getLogger(__name__)
    engines.engine_factory.configure_postgresql_factory(CONF)

    names_to_ignore = frozenset(CONF["common"].server_reserved_cert_names)

    cert_names = []
    for file in glob.glob(os.path.join(CONF.easyrsa_dir, "pki", "issued", "*.crt")):
        if (name := Path(file).stem) not in names_to_ignore:  # noqa: E741
            cert_names.append(name)
    with contexts.Context().session_manager() as s:
        for name in cert_names:
            log.info("Importing certificate %s", name)
            try:
                crt = cert.retrieve_cert_from_file(
                    os.path.join(CONF.easyrsa_dir, "pki", "issued", f"{name}.crt")
                )
                key = cert.retrieve_key_from_file(
                    os.path.join(CONF.easyrsa_dir, "pki", "private", f"{name}.key")
                )
                req = cert.retrieve_csr_from_file(
                    os.path.join(CONF.easyrsa_dir, "pki", "reqs", f"{name}.req")
                )

                csrkey = cert.dump_file_in_mem(req).decode("utf-8")
                clientkey = cert.dump_file_in_mem(key).decode("utf-8")
                clientcert = cert.dump_file_in_mem(crt).decode("utf-8")

                # Create an account for this certificate
                pin = "".join(secrets.choice(string.digits) for _ in range(10))
                account = models.Account(
                    user_id=name,
                    account_name=name,
                    pin=pin,
                    auth_type="cert_and_password",
                )
                account.save(session=s)
                log.info(
                    "Created account %s (%s), PIN: %s",
                    account.uuid,
                    account.account_name,
                    pin,
                )

                certificate = models.Certificate(
                    user_id=name,
                    account=account,
                    serial=decimal.Decimal(crt.get_serial_number()),
                    key=clientkey,
                    req=csrkey,
                    cert=clientcert,
                )
                certificate.save(session=s)

            except Exception as e:
                log.exception("Failed to import certificate %s: %s", name, e)
                break


if __name__ == "__main__":
    main()
