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
import datetime
import decimal
import hashlib
import hmac as hmac_lib
import secrets
import uuid

import netaddr
from oslo_config import cfg
from restalchemy.common import contexts
from restalchemy.common import exceptions as ra_exceptions
from restalchemy.dm import filters as dm_filters
from restalchemy.dm import models
from restalchemy.dm import properties
from restalchemy.dm import relationships
from restalchemy.dm import types
from restalchemy.dm import types_network
from restalchemy.storage.sql import orm

from exordos_vpn.common import cert
from exordos_vpn.common import constants as c
from exordos_vpn.common import crypto
from exordos_vpn.common import firewall_kinds

CONF = cfg.CONF


class CommonModel(
    models.ModelWithTimestamp,
    models.ModelWithUUID,
    orm.SQLStorableMixin,
):
    pass


class Network(CommonModel, models.ModelWithNameDesc):
    __tablename__ = "networks"

    subnets = properties.property(
        types.TypedList(types_network.IpWithMask()),
        required=True,
    )

    def max_offset(self):
        """Return the max usable address offset across all subnets in this network."""
        if not self.subnets:
            raise ValueError(f"Network '{self.name}' has no subnets configured")
        total_capacity = sum(
            max(netaddr.IPNetwork(str(s)).size - 3, 0) for s in self.subnets
        )
        return total_capacity + 1

    def ip_for_offset(self, offset):
        """Resolve a sequential address offset to (ip_str, netmask_str) from this network's subnets.

        Offsets start at 2 (offset 1 is the VPN server address in each subnet).
        Subnets are filled in order; each contributes size-3 client slots
        (positions 2..size-2, excluding network address, server, and broadcast).
        """
        if not self.subnets:
            raise ValueError(f"Network '{self.name}' has no subnets configured")
        remaining = offset - 2
        for subnet_str in self.subnets:
            subnet = netaddr.IPNetwork(str(subnet_str))
            capacity = max(subnet.size - 3, 0)
            if remaining < capacity:
                return str(subnet.network + remaining + 2), str(subnet.netmask)
            remaining -= capacity
        raise ValueError(
            f"Offset {offset} exceeds total capacity of network '{self.name}'"
        )


MIN_PIN_LENGTH = 6


class InvalidPinError(ra_exceptions.RestAlchemyException):
    message = f"PIN must be at least {MIN_PIN_LENGTH} characters long"
    code = 400


def _generate_salt(length=18):
    """Generate a random base64 salt."""
    return base64.b64encode(secrets.token_bytes(length)).decode("utf-8")


def _hash_auth_token(account_name, password, global_salt):
    """HMAC-SHA256 of (account_name:password) keyed with the global salt."""
    raw_salt = base64.b64decode(global_salt)
    return hmac_lib.new(
        raw_salt,
        f"{account_name}:{password}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


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
    network = relationships.relationship(Network, required=True)
    auth_type = properties.property(
        types.Enum(("password_only", "cert_and_password")),
        default="password_only",
    )
    status = properties.property(types.Enum(("ACTIVE", "DISABLED")), default="ACTIVE")
    pin_length = properties.property(
        types.Integer(min_value=6, max_value=128), default=6
    )
    address_offset = properties.property(
        types.AllowNone(types.Integer(min_value=2, max_value=4096))
    )
    pin_salt = properties.property(types.String(), required=False)
    pin_hash = properties.property(types.String(), required=True)
    network_access_type = properties.property(
        types.Enum(("ALL", "RESTRICTED")),
        default="RESTRICTED",
    )
    network_access_tags = properties.property(
        types.TypedList(types.String()),
        default=[],
    )

    @classmethod
    def allocate_address_offset(cls, network, session=None):
        session = session or contexts.Context().get_session()

        max_offset = network.max_offset()
        # offset 1 is reserved for the server
        res = session.execute(
            """\
SELECT s.i AS unused_number
FROM generate_series(2, %s) s(i)
LEFT OUTER JOIN accounts a ON a.address_offset = s.i AND a.network = %s
WHERE a.address_offset IS null
limit 1;""",
            (max_offset, str(network.uuid)),
        ).fetchall()
        if len(res) > 0:
            return int(res[0]["unused_number"])
        raise NotImplementedError(
            "No unused address offsets found. Please increase the range "
            "of subnet or free disabled offsets!"
        )

    def __init__(self, account_name=None, pin=None, address_offset=None, **kwargs):
        account_name = account_name or kwargs.get("user_id", "")

        if not pin or len(pin) < MIN_PIN_LENGTH:
            raise InvalidPinError()

        pin_salt = _generate_salt()
        global_salt = CONF[c.COMMON_DOMAIN].global_salt
        pin_hash = _generate_pin_hash(pin, pin_salt, global_salt)

        if not address_offset:
            address_offset = self.allocate_address_offset(kwargs["network"])

        super().__init__(
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

    def check_auth_cache(self, password):
        """Return True if password matches a non-expired cached auth token."""
        if CONF[c.COMMON_DOMAIN].auth_cache_ttl_hours == 0:
            return False
        cache = AccountAuthCache.objects.get_one_or_none(
            filters={"account": dm_filters.EQ(self)},
        )
        if not cache or not cache.auth_cache_hash or not cache.auth_cache_expires_at:
            return False
        now = datetime.datetime.now(datetime.timezone.utc)
        if cache.auth_cache_expires_at <= now:
            return False
        global_salt = CONF[c.COMMON_DOMAIN].global_salt
        candidate = _hash_auth_token(self.account_name, password, global_salt)
        return hmac_lib.compare_digest(candidate, cache.auth_cache_hash)

    def update_auth_cache(self, password, session=None):
        """Refresh the cached auth token (sliding window, TTL from config)."""
        ttl_hours = CONF[c.COMMON_DOMAIN].auth_cache_ttl_hours
        if ttl_hours == 0:
            return
        global_salt = CONF[c.COMMON_DOMAIN].global_salt
        new_hash = _hash_auth_token(self.account_name, password, global_salt)
        # add 30 seconds for clients such as pritunl (reneg-sec drift)
        new_expires_at = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(hours=ttl_hours, seconds=30)
        cache = AccountAuthCache.objects.get_one_or_none(
            filters={"account": dm_filters.EQ(self)},
            session=session,
        )
        if cache is not None:
            cache.auth_cache_hash = new_hash
            cache.auth_cache_expires_at = new_expires_at
            cache.save(session=session)
        else:
            AccountAuthCache(
                account=self,
                auth_cache_hash=new_hash,
                auth_cache_expires_at=new_expires_at,
            ).save(session=session)

    def get_otp_devices(self, session=None):
        """Get all OTP devices for this account."""
        session = session or contexts.Context().get_session()
        rels = AccountOtpDevice.objects.get_all(
            session=session,
            filters={"account": dm_filters.EQ(self)},
        )
        return [rel.otp_device for rel in rels]

    def disable(self, session=None):
        self.status = "DISABLED"
        self.save(session=session)


class AccountAuthCache(models.ModelWithUUID, orm.SQLStorableMixin):
    """Auth cache for reconnects — separate table so updates don't touch accounts.updated_at."""

    __tablename__ = "account_auth_cache"

    account = relationships.relationship(Account, required=True)
    auth_cache_hash = properties.property(types.AllowNone(types.String()))
    auth_cache_expires_at = properties.property(types.AllowNone(types.UTCDateTimeZ()))


class Service(CommonModel, models.ModelWithNameDesc):
    __tablename__ = "services"

    subnets = properties.property(
        types.TypedList(types_network.IpWithMask()),
        default=[],
    )
    domains = properties.property(
        types.TypedList(types_network.Hostname()),
        default=[],
    )
    tags = properties.property(
        types.TypedList(types.String()),
        default=[],
    )
    kinds = properties.property(
        types.TypedList(firewall_kinds.FirewallKindSelectorType),
        default=lambda: [firewall_kinds.FirewallKindAny()],
    )
    # Gateway IP of a separate proxy/router box; when set, traffic to this
    # service's subnets/domains is routed via this nexthop instead of the
    # VPN gateway's own default route (see server_agent._reconcile_routes).
    nexthop = properties.property(
        types.AllowNone(types_network.IPAddress()),
        default=None,
    )

    def validate(self):
        """Runs on construction and on every UPDATE (restalchemy calls it
        from Model.pour and orm update()), so a service can't lose its last
        subnet/domain through service-reset/remove-* either."""
        super().validate()
        if not self.subnets and not self.domains:
            raise ValueError("Service requires at least one of subnets/domains")


class OtpDevice(CommonModel):
    __tablename__ = "otp_devices"

    user_id = properties.property(types.String(), required=True)
    name = properties.property(types.String(), default="")
    otp_secret = properties.property(types.String(), required=True)
    otp_type = properties.property(types.Enum(("totp",)), default="totp")
    status = properties.property(types.Enum(("ACTIVE", "DISABLED")), default="ACTIVE")

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
            session.execute("SELECT nextval('serial_number') as serial").fetchall()[0][
                "serial"
            ]
        )

    @classmethod
    def issue_certificate(cls, common_name, serial):
        serial = int(serial)
        # TODO: support client self-generated requests
        cacert = cert.retrieve_cert_from_file(CONF[c.COMMON_DOMAIN].ca_cert_file)
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

    def __init__(self, serial=None, req=None, key=None, cert=None, **kwargs):
        my_uuid = uuid.uuid4()
        common_name = kwargs["account"].account_name
        if not common_name:
            raise ValueError("Account is required for certificate creation")
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
            uuid=my_uuid, req=req, key=key, cert=cert, serial=serial, **kwargs
        )

    def disable(self, session=None):
        self.account.disable(session=session)


class AccountOtpDevice(models.ModelWithUUID, orm.SQLStorableMixin):
    """Many-to-many relationship between Account and OtpDevice."""

    __tablename__ = "account_otp_devices"

    account = relationships.relationship(Account, required=True)
    otp_device = relationships.relationship(OtpDevice, required=True)
