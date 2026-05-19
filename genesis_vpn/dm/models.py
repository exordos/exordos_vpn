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

import base64
import decimal
import hashlib
import secrets
import uuid

from oslo_config import cfg
from restalchemy.common import contexts
from restalchemy.common import exceptions as ra_exceptions
from restalchemy.dm import models
from restalchemy.dm import properties
from restalchemy.dm import relationships
from restalchemy.dm import types
from restalchemy.storage.sql import orm

from genesis_vpn.common import cert
from genesis_vpn.common import config
from genesis_vpn.common import constants as c
from genesis_vpn.common import crypto


CONF = cfg.CONF


class CommonModel(
    models.ModelWithTimestamp,
    models.ModelWithUUID,
    orm.SQLStorableMixin,
):
    pass


class InvalidPinError(ra_exceptions.RestAlchemyException):
    message = "PIN must be at least 10 characters long"
    code = 400


MIN_PIN_LENGTH = 10


def _generate_salt(length=18):
    """Generate a random base64 salt."""
    return base64.b64encode(secrets.token_bytes(length)).decode("utf-8")


def _generate_pin_hash(pin, pin_salt, global_salt):
    """Hash a PIN with PBKDF2-SHA512 using per-record and global salts."""
    raw_pin_salt = base64.b64decode(pin_salt)
    raw_global_salt = base64.b64decode(global_salt)

    hashed = hashlib.pbkdf2_hmac(
        "sha512",
        pin.encode("utf-8"),
        raw_pin_salt + raw_global_salt,
        251685,
    )
    return hashed.hex()


class Account(CommonModel):
    __tablename__ = "accounts"

    user_id = properties.property(types.String(), required=True)
    account_name = properties.property(types.String(), required=True)
    auth_type = properties.property(
        types.Enum(("password_only", "cert_and_password")),
        default="password_only",
    )
    status = properties.property(
        types.Enum(("ACTIVE", "DISABLED")), default="ACTIVE"
    )
    pin_length = properties.property(
        types.Integer(min_value=10, max_value=128), default=10
    )
    address_offset = properties.property(
        types.AllowNone(types.Integer(min_value=2, max_value=4096))
    )
    pin_salt = properties.property(
        types.String(), required=False
    )
    pin_hash = properties.property(
        types.String(), required=True
    )

    @classmethod
    def allocate_address_offset(cls, session=None):
        session = session or contexts.Context().get_session()

        # 1 is reserved for server!
        res = session.execute(
            """\
SELECT s.i AS unused_number
FROM generate_series(2, %s) s(i)
LEFT OUTER JOIN accounts a ON a.address_offset = s.i
WHERE a.address_offset IS null
limit 1;""",
            (config.get_minimal_subnet_size(),),
        ).fetchall()
        if len(res) > 0:
            return int(res[0]["unused_number"])
        raise NotImplementedError(
            "No unused address offsets found. Please increase the range "
            "of subnet or free disabled offsets!"
        )

    def __init__(
        self,
        account_name=None,
        pin=None,
        address_offset=None,
        **kwargs
    ):
        my_uuid = uuid.uuid4()
        account_name = account_name or str(my_uuid)

        if not pin or len(pin) < MIN_PIN_LENGTH:
            raise InvalidPinError()

        pin_salt = _generate_salt()
        global_salt = CONF[c.COMMON_DOMAIN].global_salt
        pin_hash = _generate_pin_hash(pin, pin_salt, global_salt)

        if not address_offset:
            address_offset = self.allocate_address_offset()

        super().__init__(
            uuid=my_uuid,
            account_name=account_name,
            pin_salt=pin_salt,
            pin_hash=pin_hash,
            address_offset=address_offset,
            **kwargs,
        )

    def check_pin(self, pin):
        """Verify a PIN against the stored hash."""
        global_salt = CONF[c.COMMON_DOMAIN].global_salt
        expected = _generate_pin_hash(pin, self.pin_salt, global_salt)
        return expected == self.pin_hash

    def disable(self, session=None):
        self.status = "DISABLED"
        self.save(session=session)


class OtpDevice(CommonModel):
    __tablename__ = "otp_devices"

    account = relationships.relationship(Account, required=True)
    name = properties.property(types.String(), default="")
    otp_secret = properties.property(types.String(), required=True)
    otp_type = properties.property(
        types.Enum(("totp",)), default="totp"
    )
    status = properties.property(
        types.Enum(("ACTIVE", "DISABLED")), default="ACTIVE"
    )

    def __init__(self, otp_secret, **kwargs):
        # Encrypt the OTP secret before storing
        encrypted = crypto.encrypt_otp_secret(otp_secret)
        super().__init__(otp_secret=encrypted, **kwargs)

    def get_decrypted_secret(self):
        """Decrypt and return the base32 TOTP secret."""
        return crypto.decrypt_otp_secret(self.otp_secret)

    def disable(self, session=None):
        self.status = "DISABLED"
        self.save(session=session)


class Certificate(CommonModel):
    __tablename__ = "certificates"

    account = relationships.relationship(Account, required=True)
    user_id = properties.property(types.String(), required=True)
    key = properties.property(types.String())
    req = properties.property(types.String())
    cert = properties.property(types.String())
    # serial is a really large int, postgres prefers to interpret
    #  variable-length integers as numeric (i.e. decimal for psycopg2).
    serial = properties.property(types.Decimal())

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

    @property
    def common_name(self):
        """Common name is owned by Account."""
        return self.account.account_name

    @property
    def address_offset(self):
        """Address offset is owned by Account."""
        return self.account.address_offset

    @property
    def status(self):
        """Status is owned by Account."""
        return self.account.status

    def __init__(
        self,
        serial=None,
        req=None,
        key=None,
        cert=None,
        **kwargs
    ):
        my_uuid = uuid.uuid4()
        common_name = kwargs["account"].account_name
        if not common_name:
            raise ValueError(
                "Account is required for certificate creation"
            )
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

        super().__init__(
            uuid=my_uuid,
            req=req,
            key=key,
            cert=cert,
            serial=serial,
            **kwargs
        )

    def disable(self, session=None):
        self.account.disable(session=session)
