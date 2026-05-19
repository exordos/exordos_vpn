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

import qrcode
from rich.console import Console
from rich.table import Table

from oslo_config import cfg
import pyotp
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


def _generate_pin(length=10):
    """Generate a random numeric PIN of the given length."""
    alphabet = string.digits
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

    return (
        f"GenesisVPN Credentials\n"
        f"=====================\n\n"
        f"Login: {account_name}\n"
        f"PIN: {pin}\n\n"
        f"OTP Setup\n"
        f"---------\n"
        f"1. Scan the QR code below with your authenticator app\n"
        f"2. When connecting, enter: PIN + OTP code\n\n"
        f"{qr_text}\n\n"
        f"OTP URI: {otp_uri}\n"
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
            "uuid": dm_filters.EQ(otp_uuid),
            "account": dm_filters.EQ(str(account.uuid)),
        }
        device = models.OtpDevice.objects.get_one(
            session=session, filters=filters
        )
        return device, False  # (device, created=False)

    filters = {"account": dm_filters.EQ(str(account.uuid))}
    devices = models.OtpDevice.objects.get_all(
        session=session, filters=filters
    )

    if len(devices) == 0:
        # No OTP device exists — create one
        otp_secret = pyotp.random_base32()
        device = models.OtpDevice(
            otp_secret=otp_secret,
            name="Default",
            account=account,
        )
        device.save(session=session)
        return device, True  # (device, created)
    elif len(devices) == 1:
        return devices[0], False
    else:
        CONSOLE.print(
            f"Account has {len(devices)} OTP devices. "
            f"Please specify --otp-uuid."
        )
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("uuid", style="dim", width=36)
        table.add_column("name")
        table.add_column("status")
        for d in devices:
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
        "--name", type=str.lower, default=None,
        help="Account name (auto-generated if not provided)"
    )
    account_create_action.add_argument(
        "--pin-length", type=int, default=10,
        help="PIN length (min 10, auto-generated)"
    )
    account_create_action.add_argument("--disable-pbin", action="store_true")

    account_list_action = subparsers.add_parser("account-list")
    account_list_action.add_argument("--user-id", required=False)

    account_disable_action = subparsers.add_parser("account-disable")
    account_disable_action.add_argument("uuid")

    account_gen_config_action = subparsers.add_parser("account-generate-config")
    account_gen_config_action.add_argument("uuid")
    account_gen_config_action.add_argument("--otp-uuid", default=None,
        help="OTP device uuid (required if account has multiple OTP devices)"
    )
    account_gen_config_action.add_argument("--disable-pbin", action="store_true")

    # Certificate management commands
    cert_list_action = subparsers.add_parser("cert-list")
    cert_list_action.add_argument("--user-id", required=False)

    # OTP device management commands
    otp_add_action = subparsers.add_parser("otp-add")
    otp_add_action.add_argument("account_uuid")
    otp_add_action.add_argument(
        "--name", default="Default", help="Device name"
    )

    otp_list_action = subparsers.add_parser("otp-list")
    otp_list_action.add_argument("account_uuid")

    otp_remove_action = subparsers.add_parser("otp-remove")
    otp_remove_action.add_argument("uuid")


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
        if not conf.disable_pbin and CONF[c.COMMON_DOMAIN].get(
            "privatebin_endpoint"
        ):
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
        print(
            f"Upload to pbin failed, feel free to retry, error: {e}"
        )


def account_create(session, conf):
    pin = _generate_pin(length=conf.pin_length)
    generate_certs = CONF[c.COMMON_DOMAIN].generate_certs
    auth_type = "cert_and_password" if generate_certs else "password_only"

    kwargs = {}
    kwargs["user_id"] = conf.user_id
    kwargs["pin"] = pin
    kwargs["pin_length"] = conf.pin_length
    kwargs["auth_type"] = auth_type
    if conf.name:
        kwargs["account_name"] = conf.name

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
    otp_secret = device.otp_secret

    # Generate OTP provisioning URI and QR code
    otp_uri = pyotp.TOTP(otp_secret).provisioning_uri(
        name=account.account_name, issuer_name="GenesisVPN"
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
    CONSOLE.print(
        "Scan the QR code with your authenticator app."
    )

    # Generate config file and send everything to PrivateBin
    conf.uuid = account.uuid
    config_file = account_generate_config(session, conf)

    credentials_text = _build_credentials_text(
        account.account_name, pin, otp_uri
    )
    pbin_send(conf, text=credentials_text, config_file=config_file)


def account_list(session, conf):
    filters = {}
    if conf.user_id:
        filters["user_id"] = dm_filters.EQ(conf.user_id)
    accounts = models.Account.objects.get_all(
        session=session, filters=filters
    )
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
    filters = {}
    filters["uuid"] = dm_filters.EQ(conf.uuid)
    account = models.Account.objects.get_one(session=session, filters=filters)
    account.disable(session=session)

    CONSOLE.print(f"Account {account.uuid} ({account.account_name}) disabled")


def account_generate_config(session, conf):
    """Generate .ovpn config file. Returns the config file path."""
    filters = {}
    filters["uuid"] = dm_filters.EQ(conf.uuid)
    account = models.Account.objects.get_one(session=session, filters=filters)

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
        cert = models.Certificate.objects.get_one(
            session=session, filters=cert_filters
        )
        with open(config_file, "w") as f:
            f.write(ovpn_config.generate_ovpn_config(cert))
    else:
        # password_only — 2FA config without cert/key
        with open(config_file, "w") as f:
            f.write(ovpn_config.generate_ovpn_config(account))

    CONSOLE.print(f"Configuration file generated at {config_file}")
    return config_file


def otp_add(session, conf):
    filters = {"uuid": dm_filters.EQ(conf.account_uuid)}
    account = models.Account.objects.get_one(session=session, filters=filters)

    secret = pyotp.random_base32()
    device = models.OtpDevice(
        otp_secret=secret,
        name=conf.name,
        account=account,
    )
    device.save(session=session)

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=account.account_name, issuer_name="GenesisVPN"
    )
    CONSOLE.print(f"OTP device added: {device.uuid}")
    CONSOLE.print(f"Device name: {device.name}")
    CONSOLE.print(f"Secret (base32): {secret}")
    CONSOLE.print("[bold]OTP QR Code:[/bold]")
    _print_otp_qrcode(uri)
    CONSOLE.print(
        "Scan the QR code with your authenticator app."
    )


def otp_list(session, conf):
    filters = {"account": dm_filters.EQ(conf.account_uuid)}
    devices = models.OtpDevice.objects.get_all(
        session=session, filters=filters
    )
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("uuid", style="dim", width=36)
    table.add_column("name")
    table.add_column("otp_type")
    table.add_column("status", justify="right")
    for device in devices:
        table.add_row(
            str(device.uuid),
            device.name,
            device.otp_type,
            device.status,
        )

    CONSOLE.print(table)


def otp_remove(session, conf):
    filters = {"uuid": dm_filters.EQ(conf.uuid)}
    device = models.OtpDevice.objects.get_one(
        session=session, filters=filters
    )
    device.disable(session=session)

    CONSOLE.print(f"OTP device {device.uuid} ({device.name}) disabled")


FUNC_MAPPING = {
    "account-create": account_create,
    "account-list": account_list,
    "account-disable": account_disable,
    "account-generate-config": account_generate_config,
    "cert-list": cert_list,
    "otp-add": otp_add,
    "otp-list": otp_list,
    "otp-remove": otp_remove,
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
