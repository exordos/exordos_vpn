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
import uuid

from oslo_config import cfg
from restalchemy.common import contexts
from restalchemy.dm import models
from restalchemy.dm import properties
from restalchemy.dm import relationships
from restalchemy.dm import types
from restalchemy.dm import types_dynamic
from restalchemy.storage.sql import orm

from genesis_vpn.common import constants as c
from genesis_vpn.common import cert


CONF = cfg.CONF


class CommonModel(
    models.ModelWithTimestamp,
    models.ModelWithUUID,
    orm.SQLStorableMixin,
):
    pass


class Certificate(CommonModel):
    __tablename__ = "certificates"

    common_name = properties.property(types.String(), required=True)
    name = properties.property(types.String(), default="")
    status = properties.property(
        types.Enum(("ACTIVE", "DISABLED")), default="ACTIVE"
    )
    user_id = properties.property(types.String(), required=True)
    key = properties.property(types.String())
    req = properties.property(types.String())
    cert = properties.property(types.String())
    # serial is a really large int, postgres prefers to interpret
    #  variable-length integers as numeric (i.e. decimal for psycopg2).
    serial = properties.property(types.Decimal())
    address_offset = properties.property(
        types.AllowNone(types.Integer(min_value=2, max_value=4096))
    )

    @classmethod
    def get_next_serial(cls, session=None):
        session = session or contexts.Context().get_session()
        return decimal.Decimal(
            session.execute(
                "SELECT nextval('serial_number') as serial"
            ).fetchall()[0]["serial"]
        )

    @classmethod
    def issue_certificate(cls, common_name, serial):
        serial = int(serial)
        # TODO: support client self-generated requests
        cacert = cert.retrieve_cert_from_file(
            CONF[c.COMMON_DOMAIN].ca_cert_file
        )
        cakey = cert.retrieve_key_from_file(CONF[c.COMMON_DOMAIN].ca_key_file)

        key = cert.make_keypair()
        csr = cert.make_csr(key, common_name)
        crt = cert.create_slave_certificate(
            csr,
            cakey,
            cacert,
            serial,
            validity_days=CONF[c.COMMON_DOMAIN].new_cert_validity_days,
        )

        # Now we have a successfully signed certificate. We must now
        # create a .ovpn file and then dump it somewhere.
        csrkey = cert.dump_file_in_mem(csr).decode("utf-8")
        clientkey = cert.dump_file_in_mem(key).decode("utf-8")
        clientcert = cert.dump_file_in_mem(crt).decode("utf-8")

        # Logic to issue a certificate
        return csrkey, clientkey, clientcert

    @classmethod
    def allocate_address_offset(self, session=None):
        # TODO: reuse freed offsets
        session = session or contexts.Context().get_session()
        return (
            int(
                session.execute(
                    "SELECT coalesce(max(address_offset), 1) as max_offset from certificates"
                ).fetchall()[0]["max_offset"]
            )
            + 1
        )

    def __init__(
        self,
        common_name=None,
        address_offset=None,
        serial=None,
        req=None,
        key=None,
        cert=None,
        name=None,
        **kwargs
    ):
        my_uuid = uuid.uuid4()
        common_name = common_name or str(my_uuid)
        serial = serial or self.get_next_serial()
        # If no certificate is provided, issue one
        # TODO: we can support reqs and keys as well,
        #  but for now we only support certificates.
        if not cert:
            req, key, cert = self.issue_certificate(common_name, serial)
        else:
            if not req or not key:
                raise ValueError(
                    "If a certificate is provided, req and key must also be provided"
                )

        if not address_offset:
            address_offset = self.allocate_address_offset()

        name = name or str(serial)

        super().__init__(
            uuid=my_uuid,
            common_name=common_name,
            address_offset=address_offset,
            req=req,
            key=key,
            cert=cert,
            serial=serial,
            name=name,
            **kwargs
        )

    def disable(self, session=None):
        self.status = "DISABLED"
        self.save(session=session)
