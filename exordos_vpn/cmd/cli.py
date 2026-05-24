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

import io
import logging
import os
import secrets
import string
import sys
import uuid

import jinja2

import netaddr
import pyotp
import qrcode
from oslo_config import cfg
from restalchemy.common import config_opts as ra_config_opts
from restalchemy.common import contexts
from restalchemy.dm import filters as dm_filters
from restalchemy.storage.sql import engines
from rich.console import Console
from rich.table import Table

from exordos_vpn.common import config
from exordos_vpn.common import constants as c
from exordos_vpn.common import firewall_kinds
from exordos_vpn.common import log as infra_log
from exordos_vpn.common import ovpn_config
from exordos_vpn.common import privatebin
from exordos_vpn.dm import models


CONSOLE = Console()
CONF = cfg.CONF
ra_config_opts.register_posgresql_db_opts(CONF)
config.register_service_config_opts()


def _resolve_account(session, identifier):
    """Resolve an account by UUID or account_name.

    Tries UUID lookup first, then falls back to account_name.
    Raises SystemExit if account is not found.
    """
    # Try UUID lookup if identifier is a valid UUID
    try:
        uuid.UUID(identifier)
    except ValueError:
        is_uuid = False
    else:
        is_uuid = True

    if is_uuid:
        filters = {"uuid": dm_filters.EQ(identifier)}
        res = models.Account.objects.get_one_or_none(session=session, filters=filters)
        if res:
            return res

    # Try account_name
    filters = {"account_name": dm_filters.EQ(identifier)}
    res = models.Account.objects.get_one_or_none(session=session, filters=filters)
    if res:
        return res

    CONSOLE.print(f"[red]Account not found: {identifier}[/red]")
    raise SystemExit(1)


def _generate_pin(length=6):
    """Generate a random PIN with letters and digits of the given length."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_credentials_text(account_name, pin, otp_uri):
    """Build credentials text for the user."""
    # Generate QR code as ASCII text for inclusion in the message
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
    )
    qr.add_data(otp_uri)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf)
    qr_text = buf.getvalue()

    template_file = CONF.find_file(
        CONF[c.COMMON_DOMAIN].credentials_template
    )
    with open(template_file, "r") as f:
        template = jinja2.Template(f.read())
    return template.render(
        account_name=account_name,
        pin=pin,
        qr_text=qr_text,
        otp_uri=otp_uri,
    )


def _resolve_otp_device(session, account, otp_uuid=None):
    """Resolve which OTP device to use for an account.

    - If otp_uuid is explicitly provided, use that device.
    - If no OTP devices exist, create one and return it.
    - If exactly one OTP device exists, use it.
    - If more than one exists, raise an error asking to specify.
    """
    if otp_uuid:
        filters = {
            "otp_device": dm_filters.EQ(otp_uuid),
            "account": dm_filters.EQ(account),
        }
        rel = models.AccountOtpDevice.objects.get_one(session=session, filters=filters)
        return rel.otp_device, False  # (device, created=False)

    filters = {"account": dm_filters.EQ(account)}
    rels = models.AccountOtpDevice.objects.get_all(session=session, filters=filters)

    if len(rels) == 0:
        # No OTP device exists — create one
        otp_secret = pyotp.random_base32()
        device = models.OtpDevice(
            otp_secret=otp_secret,
            name="Default",
            user_id=account.user_id,
        )
        device.save(session=session)
        rel = models.AccountOtpDevice(account=account, otp_device=device)
        rel.save(session=session)
        return device, True  # (device, created)
    elif len(rels) == 1:
        return rels[0].otp_device, False
    else:
        CONSOLE.print(
            f"Account has {len(rels)} OTP devices. Please specify --otp-uuid."
        )
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("uuid", style="dim", width=36)
        table.add_column("name")
        table.add_column("status")
        for rel in rels:
            d = rel.otp_device
            table.add_row(str(d.uuid), d.name, d.status)
        CONSOLE.print(table)
        raise SystemExit(1)


def _print_otp_qrcode(uri):
    """Print OTP provisioning URI as a QR code in the terminal."""
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    qr.print_ascii()


def add_parsers(subparsers):
    # Account management commands
    account_create_action = subparsers.add_parser("account-create")
    account_create_action.add_argument("user_id", type=str.lower)
    account_create_action.add_argument(
        "--account-name",
        type=str.lower,
        default=None,
        help="Account name (auto-generated if not provided)",
    )
    account_create_action.add_argument(
        "--pin-length", type=int, default=6, help="PIN length (min 6, auto-generated)"
    )
    account_create_action.add_argument("--disable-pbin", action="store_true")

    account_list_action = subparsers.add_parser("account-list")
    account_list_action.add_argument("--user-id", required=False)

    account_disable_action = subparsers.add_parser("account-disable")
    account_disable_action.add_argument("account", help="Account UUID or name")

    account_gen_config_action = subparsers.add_parser("account-generate-config")
    account_gen_config_action.add_argument("account", help="Account UUID or name")
    account_gen_config_action.add_argument(
        "--otp-uuid",
        default=None,
        help="OTP device uuid (required if account has multiple OTP devices)",
    )
    account_gen_config_action.add_argument("--disable-pbin", action="store_true")

    # Certificate management commands
    cert_list_action = subparsers.add_parser("cert-list")
    cert_list_action.add_argument("--user-id", required=False)

    # OTP device management commands
    otp_add_action = subparsers.add_parser("otp-add")
    otp_add_action.add_argument("account", help="Account UUID or name")
    otp_add_action.add_argument("--name", default="Default", help="Device name")

    otp_list_action = subparsers.add_parser("otp-list")
    otp_list_action.add_argument("account", help="Account UUID or name")

    otp_remove_action = subparsers.add_parser("otp-remove")
    otp_remove_action.add_argument("uuid")

    # Service management commands
    service_create_action = subparsers.add_parser("service-create")
    service_create_action.add_argument("name", type=str.lower)
    service_create_action.add_argument(
        "--subnets",
        required=True,
        help="Comma-separated list of subnets (e.g. 10.0.0.0/8,172.16.0.0/12)",
    )
    service_create_action.add_argument(
        "--tags",
        default="",
        help="Comma-separated tags (e.g. finance,engineering)",
    )
    service_create_action.add_argument(
        "--description", default="", help="Service description"
    )
    service_create_action.add_argument(
        "--kinds",
        default="",
        help=(
            "Comma-separated list of firewall kinds. "
            "Format: kind:type[,port-min-port] "
            "(e.g. 'any,tcp:80-443,udp:53' or empty for any)"
        ),
    )

    subparsers.add_parser("service-list")

    service_delete_action = subparsers.add_parser("service-delete")
    service_delete_action.add_argument("uuid")

    # Account network access commands
    account_network_access_action = subparsers.add_parser("account-set-network-access")
    account_network_access_action.add_argument("account", help="Account UUID or name")
    account_network_access_action.add_argument(
        "--access-type",
        choices=["ALL", "RESTRICTED"],
        default="RESTRICTED",
        help="Network access type (ALL or RESTRICTED)",
    )
    account_network_access_action.add_argument(
        "--tags",
        default="",
        help="Comma-separated tags for RESTRICTED access",
    )


CONF.register_cli_opt(cfg.SubCommandOpt("action", handler=add_parsers))


def cert_list(session, conf):
    filters = {}
    if conf.user_id:
        filters["user_id"] = dm_filters.EQ(conf.user_id)
    certs = models.Certificate.objects.get_all(session=session, filters=filters)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("uuid", style="dim", width=36)
    table.add_column("account_name")
    table.add_column("user_id")
    table.add_column("serial")
    for cert in certs:
        table.add_row(
            str(cert.uuid),
            cert.common_name or "-",
            cert.user_id,
            str(cert.serial),
        )

    CONSOLE.print(table)


def pbin_send(conf, text, config_file=None):
    try:
        if not conf.disable_pbin and CONF[c.COMMON_DOMAIN].get("privatebin_endpoint"):
            kwargs = {
                "text": text,
            }
            if config_file:
                kwargs["file"] = config_file
            dl_link = privatebin.send_file(
                CONF[c.COMMON_DOMAIN].privatebin_endpoint,
                **kwargs,
            )
            CONSOLE.print(
                f"One-time download link, lasts 1 week: {dl_link['full_url']}"
            )
    except Exception as e:
        print(f"Upload to pbin failed, feel free to retry, error: {e}")


def account_create(session, conf):
    pin = _generate_pin(length=conf.pin_length)
    generate_certs = CONF[c.COMMON_DOMAIN].generate_certs
    auth_type = "cert_and_password" if generate_certs else "password_only"

    kwargs = {}
    kwargs["user_id"] = conf.user_id
    kwargs["pin"] = pin
    kwargs["pin_length"] = conf.pin_length
    kwargs["auth_type"] = auth_type
    kwargs["account_name"] = conf.account_name or conf.user_id

    if not kwargs["account_name"].startswith(conf.user_id):
        kwargs["account_name"] = f"{conf.user_id}_{kwargs['account_name']}"

    account = models.Account(**kwargs)
    account.save(session=session)

    # Create a certificate if configured
    cert = None
    if generate_certs:
        cert = models.Certificate(
            user_id=conf.user_id,
            account=account,
        )
        cert.save(session=session)

    # Resolve OTP device (new account — will create one)
    device, otp_created = _resolve_otp_device(session, account)
    otp_secret = device.get_decrypted_secret()

    # Generate OTP provisioning URI and QR code
    otp_uri = pyotp.TOTP(otp_secret).provisioning_uri(
        name=account.account_name,
        issuer_name=CONF[c.COMMON_DOMAIN].otp_issuer_name,
    )

    CONSOLE.print(f"Account created with uuid: {account.uuid}")
    CONSOLE.print(f"Account name: {account.account_name}")
    CONSOLE.print(f"Auth type: {account.auth_type}")
    if cert:
        CONSOLE.print(f"Certificate uuid: {cert.uuid}")
    if otp_created:
        CONSOLE.print(f"OTP device created: {device.uuid}")
    else:
        CONSOLE.print(f"OTP device: {device.uuid} (existing)")
    CONSOLE.print()
    CONSOLE.print("[bold]Login:[/bold] " + account.account_name)
    CONSOLE.print("[bold]PIN:[/bold] " + pin, style="bold yellow")
    CONSOLE.print("[bold]OTP Secret (base32):[/bold] " + otp_secret)
    CONSOLE.print("[bold]OTP QR Code:[/bold]")
    _print_otp_qrcode(otp_uri)
    CONSOLE.print()
    CONSOLE.print("Scan the QR code with your authenticator app.")

    # Generate config file and send everything to PrivateBin
    conf.account = str(account.uuid)
    config_file = account_generate_config(session, conf)

    credentials_text = _build_credentials_text(account.account_name, pin, otp_uri)
    pbin_send(conf, text=credentials_text, config_file=config_file)


def account_list(session, conf):
    filters = {}
    if conf.user_id:
        filters["user_id"] = dm_filters.EQ(conf.user_id)
    accounts = models.Account.objects.get_all(session=session, filters=filters)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("uuid", style="dim", width=36)
    table.add_column("user_id")
    table.add_column("account_name")
    table.add_column("auth_type")
    table.add_column("status", justify="right")
    for account in accounts:
        table.add_row(
            str(account.uuid),
            account.user_id,
            account.account_name,
            account.auth_type,
            account.status,
        )

    CONSOLE.print(table)


def account_disable(session, conf):
    account = _resolve_account(session, conf.account)
    account.disable(session=session)

    CONSOLE.print(f"Account {account.uuid} ({account.account_name}) disabled")


def account_generate_config(session, conf):
    """Generate .ovpn config file. Returns the config file path."""
    account = _resolve_account(session, conf.account)

    if not os.path.exists(CONF[c.COMMON_DOMAIN].openvpn_client_configs_dir):
        os.makedirs(CONF[c.COMMON_DOMAIN].openvpn_client_configs_dir)

    config_name = f"{account.user_id}.{account.account_name}.ovpn"
    config_file = os.path.join(
        CONF[c.COMMON_DOMAIN].openvpn_client_configs_dir,
        config_name,
    )

    if account.auth_type == "cert_and_password":
        # Find the linked certificate for the standard template
        cert_filters = {"account": dm_filters.EQ(str(account.uuid))}
        cert = models.Certificate.objects.get_one(session=session, filters=cert_filters)
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o660)
        with os.fdopen(fd, "w") as f:
            f.write(ovpn_config.generate_ovpn_config(cert))
    else:
        # password_only — 2FA config without cert/key
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o660)
        with os.fdopen(fd, "w") as f:
            f.write(ovpn_config.generate_ovpn_config(account))

    CONSOLE.print(f"Configuration file generated at {config_file}")
    pbin_send(conf, text="Download your config from attachment", config_file=config_file)
    return config_file


def otp_add(session, conf):
    account = _resolve_account(session, conf.account)

    secret = pyotp.random_base32()
    device = models.OtpDevice(
        otp_secret=secret,
        name=conf.name,
        user_id=account.user_id,
    )
    device.save(session=session)
    rel = models.AccountOtpDevice(account=account, otp_device=device)
    rel.save(session=session)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=account.account_name,
        issuer_name=CONF[c.COMMON_DOMAIN].otp_issuer_name,
    )
    CONSOLE.print(f"OTP device added: {device.uuid}")
    CONSOLE.print(f"Device name: {device.name}")
    CONSOLE.print(f"Secret (base32): {secret}")
    CONSOLE.print("[bold]OTP QR Code:[/bold]")
    _print_otp_qrcode(uri)
    CONSOLE.print("Scan the QR code with your authenticator app.")


def otp_list(session, conf):
    account = _resolve_account(session, conf.account)
    filters = {"account": dm_filters.EQ(str(account.uuid))}
    rels = models.AccountOtpDevice.objects.get_all(session=session, filters=filters)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("uuid", style="dim", width=36)
    table.add_column("name")
    table.add_column("otp_type")
    table.add_column("status", justify="right")
    for rel in rels:
        device = rel.otp_device
        table.add_row(
            str(device.uuid),
            device.name,
            device.otp_type,
            device.status,
        )

    CONSOLE.print(table)


def otp_remove(session, conf):
    filters = {"uuid": dm_filters.EQ(conf.uuid)}
    device = models.OtpDevice.objects.get_one(session=session, filters=filters)
    device.disable(session=session)

    CONSOLE.print(f"OTP device {device.uuid} ({device.name}) disabled")


def _parse_kinds(kinds_str):
    """Parse kinds string into a list of FirewallKind instances."""
    if not kinds_str or not kinds_str.strip():
        return []
    kinds = []
    for kind_str in kinds_str.split(","):
        kind_str = kind_str.strip()
        if not kind_str:
            continue
        kinds.append(firewall_kinds.from_str(kind_str))
    return kinds


def service_create(session, conf):
    """Create a new service with subnets and tags."""
    subnets = [
        netaddr.IPNetwork(s.strip()) for s in conf.subnets.split(",") if s.strip()
    ]
    tags = [t.strip() for t in conf.tags.split(",") if t.strip()]
    kinds = _parse_kinds(conf.kinds)

    kwargs = {}
    if kinds:
        kwargs["kinds"] = kinds

    service = models.Service(
        name=conf.name,
        subnets=subnets,
        tags=tags,
        description=conf.description,
        **kwargs,
    )
    service.save(session=session)

    CONSOLE.print(f"Service created with uuid: {service.uuid}")
    CONSOLE.print(f"Name: {service.name}")
    CONSOLE.print(f"Subnets: {conf.subnets}")
    if service.tags:
        CONSOLE.print(f"Tags: {', '.join(service.tags)}")
    if service.description:
        CONSOLE.print(f"Description: {service.description}")
    if kinds:
        kinds_display = ", ".join(k.to_str() for k in service.kinds)
        CONSOLE.print(f"Kinds: {kinds_display}")


def service_list(session, conf):
    """List all services."""
    services = models.Service.objects.get_all(session=session)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("uuid", style="dim", width=36)
    table.add_column("name")
    table.add_column("subnets")
    table.add_column("tags")
    table.add_column("description")
    table.add_column("kinds")
    for service in services:
        kinds_str = (
            ", ".join(k.to_str() for k in service.kinds) if service.kinds else "-"
        )
        table.add_row(
            str(service.uuid),
            service.name,
            ", ".join(str(i) for i in service.subnets),
            ", ".join(service.tags) if service.tags else "-",
            service.description or "-",
            kinds_str,
        )

    CONSOLE.print(table)


def service_delete(session, conf):
    """Delete a service."""
    filters = {"uuid": dm_filters.EQ(conf.uuid)}
    service = models.Service.objects.get_one(session=session, filters=filters)
    service.delete(session=session)

    CONSOLE.print(f"Service {service.name} ({service.uuid}) deleted")


def account_set_network_access(session, conf):
    """Set network access type and tags for an account."""
    account = _resolve_account(session, conf.account)

    tags = [t.strip() for t in conf.tags.split(",") if t.strip()] if conf.tags else []

    account.network_access_type = conf.access_type
    account.network_access_tags = tags
    account.save(session=session)

    CONSOLE.print(
        f"Account {account.account_name} ({account.uuid}) "
        f"network access set to {conf.access_type}"
    )
    if tags:
        CONSOLE.print(f"Tags: {', '.join(tags)}")


FUNC_MAPPING = {
    "account-create": account_create,
    "account-list": account_list,
    "account-disable": account_disable,
    "account-generate-config": account_generate_config,
    "account-set-network-access": account_set_network_access,
    "cert-list": cert_list,
    "otp-add": otp_add,
    "otp-list": otp_list,
    "otp-remove": otp_remove,
    "service-create": service_create,
    "service-list": service_list,
    "service-delete": service_delete,
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
