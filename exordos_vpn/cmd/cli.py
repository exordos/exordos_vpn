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
import json
import os
import secrets
import string
import uuid

import click
import jinja2

import netaddr
import pyotp
import qrcode
from oslo_config import cfg
from restalchemy.common import config_opts as ra_config_opts
from restalchemy.common import contexts
from restalchemy.dm import filters as dm_filters
from restalchemy.storage import exceptions as ra_exceptions
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
config.register_service_config_opts_file_only()

# Set by _init_config from click's --config-dir
_CONFIG_DIR = None

FORMAT_TABLE = "table"
FORMAT_JSON = "json"


def _print_output(ctx, columns, rows):
    """Print data as a table or JSON depending on --format option."""
    fmt = ctx.obj.get("format", FORMAT_TABLE)
    if fmt == FORMAT_JSON:
        data = [dict(zip(columns, row)) for row in rows]
        click.echo(json.dumps(data, indent=2, default=str))
    else:
        table = Table(show_header=True, header_style="bold magenta")
        for col in columns:
            table.add_column(col)
        for row in rows:
            table.add_row(*[str(v) for v in row])
        CONSOLE.print(table)


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
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_credentials_text(account_name, pin, otp_uri=None):
    """Build credentials text for the user."""
    qr_text = ""
    if otp_uri:
        # Generate QR code as ASCII text for inclusion in the message
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_L,
        )
        qr.add_data(otp_uri)
        qr.make(fit=True)
        buf = io.StringIO()
        qr.print_ascii(out=buf)
        qr_text = buf.getvalue()

    template_name = CONF[c.COMMON_DOMAIN].credentials_template
    template_file = os.path.join(_CONFIG_DIR, template_name)
    with open(template_file, "r") as f:
        template = jinja2.Template(f.read())
    return template.render(
        account_name=account_name,
        pin=pin,
        qr_text=qr_text,
        otp_uri=otp_uri or "",
    )


def _resolve_otp_device(session, account, otp_uuid=None):
    """Resolve which OTP device to use for an account.

    One OTP device is shared across all accounts of the same user_id.

    - If otp_uuid is explicitly provided, use that device.
    - If no OTP devices exist for this user_id, create one and return it.
    - If exactly one OTP device exists for this user_id, use it.
    - If more than one exists, raise an error asking to specify.
    """
    if otp_uuid:
        filters = {"uuid": dm_filters.EQ(otp_uuid)}
        device = models.OtpDevice.objects.get_one(session=session, filters=filters)
        # Ensure the device is linked to this account
        link_filters = {
            "otp_device": dm_filters.EQ(device),
            "account": dm_filters.EQ(account),
        }
        existing = models.AccountOtpDevice.objects.get_all(
            session=session, filters=link_filters,
        )
        if not existing:
            rel = models.AccountOtpDevice(account=account, otp_device=device)
            rel.save(session=session)
        return device, False  # (device, created=False)

    # Search OTP devices by user_id (shared across all user's accounts)
    filters = {"user_id": dm_filters.EQ(account.user_id)}
    devices = models.OtpDevice.objects.get_all(session=session, filters=filters)

    if len(devices) == 0:
        # No OTP device exists for this user — create one
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
    elif len(devices) == 1:
        device = devices[0]
        # Ensure the device is linked to this account
        link_filters = {
            "otp_device": dm_filters.EQ(device),
            "account": dm_filters.EQ(account),
        }
        existing = models.AccountOtpDevice.objects.get_all(
            session=session, filters=link_filters,
        )
        if not existing:
            rel = models.AccountOtpDevice(account=account, otp_device=device)
            rel.save(session=session)
        return device, False
    else:
        CONSOLE.print("User has multiple OTP devices. Please specify --otp-uuid.")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("uuid", style="dim", width=36)
        table.add_column("name")
        table.add_column("status")
        for d in devices:
            table.add_row(str(d.uuid), d.name, d.status)
        CONSOLE.print(table)
        raise SystemExit(1)


def _secure_print(*args, **kwargs):
    """Print sensitive data only if show-credentials is enabled in config."""
    if CONF[c.COMMON_DOMAIN].show_credentials:
        CONSOLE.print(*args, **kwargs)
    else:
        CONSOLE.print("[dim](credentials hidden, see PrivateBin link)[/dim]")


def _print_otp_qrcode(uri):
    """Print OTP provisioning URI as a QR code in the terminal."""
    if not CONF[c.COMMON_DOMAIN].show_credentials:
        return
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    qr.print_ascii()


def _pbin_send(disable_pbin, text, config_file=None):
    """Send text and optionally a config file to PrivateBin."""
    try:
        if not disable_pbin and CONF[c.COMMON_DOMAIN].get("privatebin_endpoint"):
            endpoint = CONF[c.COMMON_DOMAIN].privatebin_endpoint
            if config_file:
                dl_link = privatebin.send_file(
                    endpoint,
                    text=text,
                    file=config_file,
                )
            else:
                dl_link = privatebin.send_text(endpoint, text=text)
            CONSOLE.print(
                f"One-time download link, lasts 1 week: {dl_link['full_url']}"
            )
    except Exception as e:
        print(f"Upload to pbin failed, feel free to retry, error: {e}")


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


def _init_config(config_file, config_dir):
    """Parse oslo config from the given config file/dir path."""
    global _CONFIG_DIR
    _CONFIG_DIR = config_dir
    args = []
    if config_file:
        args.append("--config-file")
        args.append(config_file)
    if config_dir:
        args.append("--config-dir")
        args.append(config_dir)
    config.parse(args)
    infra_log.configure()
    engines.engine_factory.configure_postgresql_factory(CONF)


def _ensure_config(ctx):
    """Lazily initialize oslo config and DB session on first command use."""
    if not ctx.obj.get("_config_initialized"):
        _init_config(ctx.obj["config_file"], ctx.obj["config_dir"])
        ctx.obj["session_ctx"] = contexts.Context()
        ctx.obj["_config_initialized"] = True


@click.group()
@click.option(
    "--config-file",
    envvar="EXORDOS_VPN_CONFIG",
    help="Path to the configuration file.",
)
@click.option(
    "--config-dir",
    envvar="EXORDOS_VPN_CONFIG_DIR",
    default=f"/etc/{c.GLOBAL_SERVICE_NAME}",
    show_default=True,
    help="Directory for config and template files.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice([FORMAT_TABLE, FORMAT_JSON], case_sensitive=False),
    default=FORMAT_TABLE,
    show_default=True,
    help="Output format.",
)
@click.pass_context
def cli(ctx, config_file, config_dir, output_format):
    """Exordos VPN CLI management tool."""
    ctx.ensure_object(dict)
    ctx.obj["config_file"] = config_file
    ctx.obj["config_dir"] = config_dir
    ctx.obj["format"] = output_format
    ctx.obj["_config_initialized"] = False


# --- Account commands ---


@cli.command("account-create")
@click.argument("user_id", type=str.lower)
@click.option(
    "--name",
    type=str.lower,
    default=None,
    help="Account name (auto-generated if not provided)",
)
@click.option(
    "--pin-length", type=int, default=6, help="PIN length (min 6, auto-generated)"
)
@click.option("--disable-pbin", is_flag=True, default=False)
@click.pass_context
def account_create(ctx, user_id, name, pin_length, disable_pbin):
    """Create a new account."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        pin = _generate_pin(length=pin_length)
        generate_certs = CONF[c.COMMON_DOMAIN].generate_certs
        auth_type = "cert_and_password" if generate_certs else "password_only"

        kwargs = {}
        kwargs["user_id"] = user_id
        kwargs["pin"] = pin
        kwargs["pin_length"] = pin_length
        kwargs["auth_type"] = auth_type
        kwargs["account_name"] = name or user_id

        if not kwargs["account_name"].startswith(user_id):
            kwargs["account_name"] = f"{user_id}_{kwargs['account_name']}"

        account = models.Account(**kwargs)
        try:
            account.save(session=session)
        except ra_exceptions.ConflictRecords:
            CONSOLE.print(
                f"[red]Error: Account with name "
                f"'{kwargs['account_name']}' already exists, please use another one.[/red]"
            )
            raise SystemExit(1)

        # Create a certificate if configured
        cert = None
        if generate_certs:
            cert = models.Certificate(
                user_id=user_id,
                account=account,
            )
            cert.save(session=session)

        # Resolve OTP device (new account — will create one)
        device, otp_created = _resolve_otp_device(session, account)

        otp_uri = None
        if otp_created:
            otp_secret = device.get_decrypted_secret()
            otp_uri = pyotp.TOTP(otp_secret).provisioning_uri(
                name=account.account_name,
                issuer_name=CONF[c.COMMON_DOMAIN].otp_issuer_name,
            )

        CONSOLE.print(f"Account created with uuid: {account.uuid}")
        CONSOLE.print(f"Account name: {account.account_name}")
        CONSOLE.print(f"Auth type: {account.auth_type}")
        CONSOLE.print()
        _secure_print("[bold]Login:[/bold] " + account.account_name)
        _secure_print("[bold]PIN:[/bold] " + pin, style="bold yellow")
        if cert:
            CONSOLE.print(f"Certificate uuid: {cert.uuid}")
        if otp_created:
            CONSOLE.print(f"OTP device created: {device.uuid}")
        else:
            CONSOLE.print(f"OTP device: {device.uuid} (existing)")

        if otp_created:
            _secure_print("[bold]OTP Secret (base32):[/bold] " + otp_secret)
            _secure_print("[bold]OTP QR Code:[/bold]")
            _print_otp_qrcode(otp_uri)
            CONSOLE.print()
        else:
            CONSOLE.print("[bold]OTP:[/bold] Use previously issued OTP for VPN")

        # Generate config file and send everything to PrivateBin
        config_file = _account_generate_config(
            session,
            str(account.uuid),
            disable_pbin,
            send_to_pbin=False,
        )

        credentials_text = _build_credentials_text(
            account.account_name, pin, otp_uri=otp_uri,
        )
        _pbin_send(disable_pbin, text=credentials_text, config_file=config_file)


@cli.command("account-list")
@click.option("--user-id", default=None, help="Filter by user ID")
@click.pass_context
def account_list(ctx, user_id):
    """List accounts."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {}
        if user_id:
            filters["user_id"] = dm_filters.EQ(user_id)
        accounts = models.Account.objects.get_all(session=session, filters=filters)
        columns = ["uuid", "user_id", "account_name", "auth_type", "status"]
        rows = [
            (str(a.uuid), a.user_id, a.account_name, a.auth_type, a.status)
            for a in accounts
        ]
        _print_output(ctx, columns, rows)


@cli.command("account-disable")
@click.argument("account")
@click.pass_context
def account_disable(ctx, account):
    """Disable an account."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        acc = _resolve_account(session, account)
        acc.disable(session=session)

        CONSOLE.print(f"Account {acc.uuid} ({acc.account_name}) disabled")


def _account_generate_config(
    session, account_identifier, disable_pbin=False, send_to_pbin=True
):
    """Generate .ovpn config file. Returns the config file path."""
    account = _resolve_account(session, account_identifier)

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
    if send_to_pbin:
        _pbin_send(
            disable_pbin,
            text="Download your config from attachment",
            config_file=config_file,
        )
    return config_file


@cli.command("account-generate-config")
@click.argument("account")
@click.option(
    "--otp-uuid",
    default=None,
    help="OTP device uuid (required if account has multiple OTP devices)",
)
@click.option("--disable-pbin", is_flag=True, default=False)
@click.pass_context
def account_generate_config_cmd(ctx, account, otp_uuid, disable_pbin):
    """Generate .ovpn config file for an account."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        _account_generate_config(session, account, disable_pbin)


@cli.command("account-network-show")
@click.argument("account")
@click.pass_context
def account_network_show(ctx, account):
    """Show network access rules for an account."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        acc = _resolve_account(session, account)

        CONSOLE.print(f"Account: {acc.account_name} ({acc.uuid})")
        CONSOLE.print(f"Access type: {acc.network_access_type}")
        tags = acc.network_access_tags or []
        if tags:
            CONSOLE.print(f"Tags: {', '.join(tags)}")
        else:
            CONSOLE.print("Tags: (none)")


@cli.command("account-network-reset")
@click.argument("account")
@click.option(
    "--access-type",
    type=click.Choice(["ALL", "RESTRICTED"]),
    default="RESTRICTED",
    help="Network access type",
)
@click.option("--tags", default="", help="Comma-separated tags for RESTRICTED access")
@click.pass_context
def account_reset_network_access(ctx, account, access_type, tags):
    """Reset network access type and tags for an account (full overwrite)."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        acc = _resolve_account(session, account)

        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

        # If no explicit options, confirm before resetting to defaults
        is_default = access_type == "RESTRICTED" and not tag_list
        if is_default:
            current_tags = acc.network_access_tags or []
            CONSOLE.print(
                f"Account {acc.account_name} ({acc.uuid}) "
                f"current: {acc.network_access_type}, "
                f"tags: {', '.join(current_tags) or '(none)'}"
            )
            if not click.confirm("Reset to RESTRICTED with no tags?"):
                raise SystemExit(0)

        acc.network_access_type = access_type
        acc.network_access_tags = tag_list
        acc.save(session=session)

        CONSOLE.print(
            f"Account {acc.account_name} ({acc.uuid}) "
            f"network access reset to {access_type}"
        )
        if tag_list:
            CONSOLE.print(f"Tags: {', '.join(tag_list)}")


@cli.command("account-network-add-tag")
@click.argument("account")
@click.argument("tags")
@click.pass_context
def account_add_network_tag(ctx, account, tags):
    """Add network access tags to an account."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        acc = _resolve_account(session, account)

        new_tags = [t.strip() for t in tags.split(",") if t.strip()]
        existing = list(acc.network_access_tags or [])
        added = [t for t in new_tags if t not in existing]
        acc.network_access_tags = existing + added
        acc.save(session=session)

        CONSOLE.print(
            f"Account {acc.account_name} ({acc.uuid}) tags added: {', '.join(added)}"
        )
        CONSOLE.print(f"Current tags: {', '.join(acc.network_access_tags)}")


@cli.command("account-network-remove-tag")
@click.argument("account")
@click.argument("tags")
@click.pass_context
def account_remove_network_tag(ctx, account, tags):
    """Remove network access tags from an account."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        acc = _resolve_account(session, account)

        remove_tags = [t.strip() for t in tags.split(",") if t.strip()]
        existing = list(acc.network_access_tags or [])
        acc.network_access_tags = [t for t in existing if t not in remove_tags]
        acc.save(session=session)

        CONSOLE.print(
            f"Account {acc.account_name} ({acc.uuid}) "
            f"tags removed: {', '.join(remove_tags)}"
        )
        CONSOLE.print(f"Current tags: {', '.join(acc.network_access_tags)}")


# --- OTP device commands ---


@cli.command("otp-add")
@click.argument("user_id")
@click.option("--name", default="Default", help="Device name")
@click.pass_context
def otp_add(ctx, user_id, name):
    """Add an OTP device to a user."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        secret = pyotp.random_base32()
        device = models.OtpDevice(
            otp_secret=secret,
            name=name,
            user_id=user_id,
        )
        device.save(session=session)

        # Link the device to all active accounts of this user
        filters = {
            "user_id": dm_filters.EQ(user_id),
            "status": dm_filters.EQ("ACTIVE"),
        }
        accounts = models.Account.objects.get_all(session=session, filters=filters)
        for acc in accounts:
            link_filters = {
                "otp_device": dm_filters.EQ(device),
                "account": dm_filters.EQ(acc),
            }
            existing = models.AccountOtpDevice.objects.get_all(
                session=session, filters=link_filters,
            )
            if not existing:
                rel = models.AccountOtpDevice(account=acc, otp_device=device)
                rel.save(session=session)

        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user_id,
            issuer_name=CONF[c.COMMON_DOMAIN].otp_issuer_name,
        )
        CONSOLE.print(f"OTP device added: {device.uuid}")
        CONSOLE.print(f"Device name: {device.name}")
        _secure_print(f"Secret (base32): {secret}")
        _secure_print("[bold]OTP QR Code:[/bold]")
        _print_otp_qrcode(uri)
        CONSOLE.print("Scan the QR code with your authenticator app.")


@cli.command("otp-list")
@click.argument("user_id")
@click.pass_context
def otp_list(ctx, user_id):
    """List OTP devices for a user."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"user_id": dm_filters.EQ(user_id)}
        devices = models.OtpDevice.objects.get_all(session=session, filters=filters)
        columns = ["uuid", "name", "otp_type", "status", "accounts"]
        rows = []
        for d in devices:
            link_filters = {"otp_device": dm_filters.EQ(d)}
            rels = models.AccountOtpDevice.objects.get_all(
                session=session, filters=link_filters,
            )
            account_names = ", ".join(
                r.account.account_name for r in rels
            )
            rows.append((
                str(d.uuid),
                d.name,
                d.otp_type,
                d.status,
                account_names,
            ))
        _print_output(ctx, columns, rows)


@cli.command("otp-remove")
@click.argument("uuid")
@click.pass_context
def otp_remove(ctx, uuid):
    """Disable an OTP device."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        device = models.OtpDevice.objects.get_one(session=session, filters=filters)
        device.disable(session=session)

        CONSOLE.print(f"OTP device {device.uuid} ({device.name}) disabled")


@cli.command("account-set-otp")
@click.argument("account")
@click.option("--otp-uuid", default=None, help="UUID of existing OTP device to assign")
@click.pass_context
def account_set_otp(ctx, account, otp_uuid):
    """Set or replace the OTP device for an account.

    If --otp-uuid is provided, assign that existing device.
    Otherwise, create a new OTP device for the user.
    """
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        acc = _resolve_account(session, account)

        # Remove existing OTP device links for this account
        link_filters = {"account": dm_filters.EQ(acc)}
        old_rels = models.AccountOtpDevice.objects.get_all(
            session=session, filters=link_filters,
        )
        for rel in old_rels:
            rel.delete(session=session)

        # Resolve the new OTP device
        device, otp_created = _resolve_otp_device(
            session, acc, otp_uuid=otp_uuid,
        )

        if otp_created:
            otp_secret = device.get_decrypted_secret()
            otp_uri = pyotp.TOTP(otp_secret).provisioning_uri(
                name=acc.account_name,
                issuer_name=CONF[c.COMMON_DOMAIN].otp_issuer_name,
            )
            CONSOLE.print(f"New OTP device created: {device.uuid}")
            _secure_print(f"Secret (base32): {otp_secret}")
            _secure_print("[bold]OTP QR Code:[/bold]")
            _print_otp_qrcode(otp_uri)
            CONSOLE.print("Scan the QR code with your authenticator app.")
        else:
            CONSOLE.print(f"OTP device assigned: {device.uuid} ({device.name})")
            CONSOLE.print("[bold]OTP:[/bold] Use previously issued OTP for VPN")


@cli.command("account-reset")
@click.argument("account")
@click.option(
    "--pin-length", type=int, default=6, help="PIN length (min 6, auto-generated)"
)
@click.option("--disable-pbin", is_flag=True, default=False)
@click.pass_context
def account_reset(ctx, account, pin_length, disable_pbin):
    """Reset PIN and OTP secret for an account."""
    from exordos_vpn.common import crypto
    from exordos_vpn.dm import models as dm_models

    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        acc = _resolve_account(session, account)

        CONSOLE.print(
            f"[red]Warning:[/red] Resetting account "
            f"{acc.account_name} ({acc.uuid}). "
            f"The client will [bold]no longer be able to connect[/bold] "
            f"with the old PIN and OTP code."
        )
        if not click.confirm("Proceed with reset?"):
            raise SystemExit(0)

        # Reset PIN
        new_pin = _generate_pin(length=pin_length)
        new_salt = dm_models._generate_salt()
        global_salt = CONF[c.COMMON_DOMAIN].global_salt
        acc.pin_salt = new_salt
        acc.pin_hash = dm_models._generate_pin_hash(new_pin, new_salt, global_salt)
        acc.pin_length = pin_length
        acc.save(session=session)

        # Reset OTP: find or create a device
        device, otp_created = _resolve_otp_device(session, acc)
        new_secret = pyotp.random_base32()
        device.otp_secret = crypto.encrypt_otp_secret(new_secret)
        device.save(session=session)

        # Build OTP URI and display
        otp_uri = pyotp.TOTP(new_secret).provisioning_uri(
            name=acc.account_name,
            issuer_name=CONF[c.COMMON_DOMAIN].otp_issuer_name,
        )

        CONSOLE.print(f"Account {acc.uuid} ({acc.account_name}) reset")
        _secure_print(f"[bold]New PIN:[/bold] {new_pin}", style="bold yellow")
        _secure_print(f"New OTP secret (base32): {new_secret}")
        _secure_print("[bold]OTP QR Code:[/bold]")
        _print_otp_qrcode(otp_uri)

        # Generate config file and send everything to PrivateBin
        config_file = _account_generate_config(
            session,
            str(acc.uuid),
            disable_pbin,
            send_to_pbin=False,
        )

        credentials_text = _build_credentials_text(
            acc.account_name,
            new_pin,
            otp_uri,
        )
        _pbin_send(disable_pbin, text=credentials_text, config_file=config_file)


# --- Service commands ---


@cli.command("service-create")
@click.argument("name", type=str.lower)
@click.option(
    "--subnets",
    required=True,
    help="Comma-separated list of subnets (e.g. 10.0.0.0/8,172.16.0.0/12)",
)
@click.option(
    "--tags", default="", help="Comma-separated tags (e.g. finance,engineering)"
)
@click.option("--description", default="", help="Service description")
@click.option(
    "--kinds",
    default="",
    help="Comma-separated list of firewall kinds. "
    "Format: kind:type[,port-min-port] "
    "(e.g. 'any,tcp:80-443,udp:53' or empty for any)",
)
@click.pass_context
def service_create(ctx, name, subnets, tags, description, kinds):
    """Create a new service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        subnet_list = [
            netaddr.IPNetwork(s.strip()) for s in subnets.split(",") if s.strip()
        ]
        tag_list = [t.strip() for t in tags.split(",") if t.strip()]
        kind_list = _parse_kinds(kinds)

        kwargs = {}
        if kind_list:
            kwargs["kinds"] = kind_list

        service = models.Service(
            name=name,
            subnets=subnet_list,
            tags=tag_list,
            description=description,
            **kwargs,
        )
        service.save(session=session)

        CONSOLE.print(f"Service created with uuid: {service.uuid}")
        CONSOLE.print(f"Name: {service.name}")
        CONSOLE.print(f"Subnets: {subnets}")
        if service.tags:
            CONSOLE.print(f"Tags: {', '.join(service.tags)}")
        if service.description:
            CONSOLE.print(f"Description: {service.description}")
        if kind_list:
            kinds_display = ", ".join(k.to_str() for k in service.kinds)
            CONSOLE.print(f"Kinds: {kinds_display}")


@cli.command("service-list")
@click.pass_context
def service_list(ctx):
    """List all services."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        services = models.Service.objects.get_all(session=session)
        columns = ["uuid", "name", "subnets", "tags", "description", "kinds"]
        rows = [
            (
                str(s.uuid),
                s.name,
                ", ".join(str(i) for i in s.subnets),
                ", ".join(s.tags) if s.tags else "-",
                s.description or "-",
                ", ".join(k.to_str() for k in s.kinds) if s.kinds else "-",
            )
            for s in services
        ]
        _print_output(ctx, columns, rows)


@cli.command("service-reset")
@click.argument("uuid")
@click.option("--name", default=None, help="New service name")
@click.option(
    "--subnets",
    default=None,
    help="Comma-separated list of subnets (full overwrite)",
)
@click.option(
    "--tags", default=None, help="Comma-separated tags (full overwrite)"
)
@click.option("--description", default=None, help="Service description")
@click.option(
    "--kinds",
    default=None,
    help="Comma-separated list of firewall kinds (full overwrite). "
    "Format: kind:type[,port-min-port] "
    "(e.g. 'any,tcp:80-443,udp:53' or empty for any)",
)
@click.pass_context
def service_reset(ctx, uuid, name, subnets, tags, description, kinds):
    """Reset service fields (full overwrite for each specified option)."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)

        if name is not None:
            service.name = name
        if subnets is not None:
            service.subnets = [
                netaddr.IPNetwork(s.strip()) for s in subnets.split(",") if s.strip()
            ]
        if tags is not None:
            service.tags = [t.strip() for t in tags.split(",") if t.strip()]
        if description is not None:
            service.description = description
        if kinds is not None:
            service.kinds = _parse_kinds(kinds) or [firewall_kinds.FirewallKindAny()]

        service.save(session=session)

        CONSOLE.print(f"Service {service.name} ({service.uuid}) updated")
        CONSOLE.print(f"Subnets: {', '.join(str(i) for i in service.subnets)}")
        CONSOLE.print(f"Tags: {', '.join(service.tags) or '(none)'}")
        if service.description:
            CONSOLE.print(f"Description: {service.description}")
        kinds_display = ", ".join(k.to_str() for k in service.kinds) if service.kinds else "-"
        CONSOLE.print(f"Kinds: {kinds_display}")


@cli.command("service-add-subnet")
@click.argument("uuid")
@click.argument("subnets")
@click.pass_context
def service_add_subnet(ctx, uuid, subnets):
    """Add subnets to a service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)

        new_subnets = [
            netaddr.IPNetwork(s.strip()) for s in subnets.split(",") if s.strip()
        ]
        existing = list(service.subnets or [])
        added = [s for s in new_subnets if s not in existing]
        service.subnets = existing + added
        service.save(session=session)

        CONSOLE.print(
            f"Service {service.name} ({service.uuid}) "
            f"subnets added: {', '.join(str(s) for s in added)}"
        )
        CONSOLE.print(f"Current subnets: {', '.join(str(i) for i in service.subnets)}")


@cli.command("service-remove-subnet")
@click.argument("uuid")
@click.argument("subnets")
@click.pass_context
def service_remove_subnet(ctx, uuid, subnets):
    """Remove subnets from a service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)

        remove_subnets = {
            netaddr.IPNetwork(s.strip()) for s in subnets.split(",") if s.strip()
        }
        existing = list(service.subnets or [])
        service.subnets = [s for s in existing if s not in remove_subnets]
        service.save(session=session)

        CONSOLE.print(
            f"Service {service.name} ({service.uuid}) "
            f"subnets removed: {', '.join(str(s) for s in remove_subnets)}"
        )
        CONSOLE.print(f"Current subnets: {', '.join(str(i) for i in service.subnets)}")


@cli.command("service-add-tag")
@click.argument("uuid")
@click.argument("tags")
@click.pass_context
def service_add_tag(ctx, uuid, tags):
    """Add tags to a service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)

        new_tags = [t.strip() for t in tags.split(",") if t.strip()]
        existing = list(service.tags or [])
        added = [t for t in new_tags if t not in existing]
        service.tags = existing + added
        service.save(session=session)

        CONSOLE.print(
            f"Service {service.name} ({service.uuid}) "
            f"tags added: {', '.join(added)}"
        )
        CONSOLE.print(f"Current tags: {', '.join(service.tags)}")


@cli.command("service-remove-tag")
@click.argument("uuid")
@click.argument("tags")
@click.pass_context
def service_remove_tag(ctx, uuid, tags):
    """Remove tags from a service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)

        remove_tags = [t.strip() for t in tags.split(",") if t.strip()]
        existing = list(service.tags or [])
        service.tags = [t for t in existing if t not in remove_tags]
        service.save(session=session)

        CONSOLE.print(
            f"Service {service.name} ({service.uuid}) "
            f"tags removed: {', '.join(remove_tags)}"
        )
        CONSOLE.print(f"Current tags: {', '.join(service.tags)}")


@cli.command("service-add-kind")
@click.argument("uuid")
@click.argument("kinds")
@click.pass_context
def service_add_kind(ctx, uuid, kinds):
    """Add firewall kinds to a service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)

        new_kinds = _parse_kinds(kinds)
        existing = list(service.kinds or [])
        added = [k for k in new_kinds if k not in existing]
        service.kinds = existing + added
        service.save(session=session)

        CONSOLE.print(
            f"Service {service.name} ({service.uuid}) "
            f"kinds added: {', '.join(k.to_str() for k in added)}"
        )
        kinds_display = ", ".join(k.to_str() for k in service.kinds)
        CONSOLE.print(f"Current kinds: {kinds_display}")


@cli.command("service-remove-kind")
@click.argument("uuid")
@click.argument("kinds")
@click.pass_context
def service_remove_kind(ctx, uuid, kinds):
    """Remove firewall kinds from a service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)

        remove_kinds = _parse_kinds(kinds)
        existing = list(service.kinds or [])
        service.kinds = [k for k in existing if k not in remove_kinds]
        service.save(session=session)

        CONSOLE.print(
            f"Service {service.name} ({service.uuid}) "
            f"kinds removed: {', '.join(k.to_str() for k in remove_kinds)}"
        )
        kinds_display = ", ".join(k.to_str() for k in service.kinds) if service.kinds else "-"
        CONSOLE.print(f"Current kinds: {kinds_display}")


@cli.command("service-delete")
@click.argument("uuid")
@click.pass_context
def service_delete(ctx, uuid):
    """Delete a service."""
    _ensure_config(ctx)
    session_ctx = ctx.obj["session_ctx"]
    with session_ctx.session_manager() as session:
        filters = {"uuid": dm_filters.EQ(uuid)}
        service = models.Service.objects.get_one(session=session, filters=filters)
        service.delete(session=session)

        CONSOLE.print(f"Service {service.name} ({service.uuid}) deleted")


def main():
    cli()


if __name__ == "__main__":
    main()
