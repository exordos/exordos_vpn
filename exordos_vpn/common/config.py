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

from oslo_config import cfg

from exordos_vpn.common import constants
from exordos_vpn import version


GLOBAL_SERVICE_NAME = constants.GLOBAL_SERVICE_NAME


_CONFIG_NOT_FOUND_MESSAGE = (
    "Unable to find configuration file in the"
    " default search paths (~/.%(service_name)s/, ~/,"
    " /etc/%(service_name)s/, /etc/) and the '--config-file' option!"
    % {"service_name": GLOBAL_SERVICE_NAME}
)


def parse(args):
    cfg.CONF(
        args=args,
        project=GLOBAL_SERVICE_NAME,
        version="%s %s"
        % (
            GLOBAL_SERVICE_NAME.capitalize(),
            version.version_info,
        ),
    )
    if not cfg.CONF.config_file:
        logging.warning(_CONFIG_NOT_FOUND_MESSAGE)
    return cfg.CONF.config_file


service_config_opts = [
    cfg.StrOpt(
        "openvpn-client-configs-dir",
        help="Directory to store generated openvpn configs",
        required=True,
    ),
    cfg.StrOpt(
        "server-address",
        required=True,
        help="Address of openvpn server to connect to",
    ),
    cfg.IntOpt(
        "server-port",
        required=True,
        default=1194,
        help="Port of openvpn server to connect to",
    ),
    cfg.StrOpt(
        "server-protocol",
        required=True,
        choices=["udp", "tcp"],
        default="udp",
        help="Protocol to use for connecting to the openvpn server",
    ),
    cfg.StrOpt(
        "ca-cert-file",
        required=True,
        help="Path to the CA certificate file",
    ),
    cfg.StrOpt(
        "ca-key-file",
        required=True,
        help="Path to the CA key file",
    ),
    cfg.StrOpt(
        "tls-auth-file",
        required=True,
        help="Path to the TLS authentication file",
    ),
    cfg.StrOpt(
        "config-template",
        required=True,
        default="client_config.j2",
        help="Path to the configuration template file",
    ),
    cfg.StrOpt(
        "credentials-template",
        required=True,
        default="credentials_en.md.j2",
        help="Path to the credentials markdown template file",
    ),
    cfg.IntOpt(
        "new-cert-validity-days",
        default=3650,
        help="Number of days for which the new certificate is valid",
    ),
    cfg.ListOpt(
        "server-reserved-cert-names",
        default=["server"],
        help="List of reserved common names for server certificates",
    ),
    cfg.StrOpt(
        "privatebin-endpoint",
        default="",
        help="Privatebin endpoint to paste config to. Can be disabled with --disable-pbin.",
    ),
    cfg.StrOpt(
        "global-salt",
        required=True,
        help="Global salt for PIN hashing (base64-encoded, 24+ chars). "
        "Used by ModelWithSecret mixin.",
    ),
    cfg.StrOpt(
        "otp-encryption-key",
        required=True,
        secret=True,
        help="Hex-encoded 32-byte key for AES-256-GCM encryption "
        "of OTP secrets at rest.",
    ),
    cfg.BoolOpt(
        "generate-certs",
        default=True,
        help="Whether to generate certificates for new accounts. "
        "If False, accounts are created with password_only auth.",
    ),
    cfg.StrOpt(
        "otp-issuer-name",
        default="Exordos VPN",
        help="Issuer name for OTP provisioning URI (displayed in authenticator apps).",
    ),
    cfg.BoolOpt(
        "show-credentials",
        default=False,
        help="Whether to print sensitive credentials (PIN, OTP secret, QR code) "
        "to the console. When disabled, credentials are only sent to PrivateBin.",
    ),
    cfg.IntOpt(
        "auth-cache-ttl-hours",
        default=1,
        help="How many hours a successful PIN+OTP login is cached, allowing "
        "reconnects (e.g. after device sleep) without re-entering OTP. "
        "Set to 0 to disable caching.",
    ),
]


def register_service_config_opts():
    cfg.CONF.register_cli_opts(service_config_opts, constants.COMMON_DOMAIN)


def register_service_config_opts_file_only():
    """Register service config opts for config-file only (no CLI opts).

    Use this when CLI arguments are handled by a different framework
    (e.g. click) and oslo_config should only parse the config file.
    """
    cfg.CONF.register_opts(service_config_opts, constants.COMMON_DOMAIN)


