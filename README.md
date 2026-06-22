# Exordos VPN

Genesis VPN: easy to use VPN for secure access.

## Overview

Exordos VPN is a comprehensive VPN management system built on OpenVPN with PostgreSQL backend. It provides:

- **Account Management** - User accounts with PIN-based authentication and TOTP 2FA
- **Certificate Management** - Automated SSL/TLS certificate issuance via EasyRSA
- **Service Management** - Network service definitions with subnet and firewall rule management
- **User API** - RESTful API with IAM integration for programmatic access
- **Server Agent** - Daemon on VPN servers that synchronizes configs and manages iptables firewall rules
- **Scheduler** - Background service for cleaning up unused address offsets

## Quick Start

### Installation

See `./exordos/images/install.sh`

### Running Tests

```bash
# Unit tests
tox -e py312

# Functional tests (requires PostgreSQL)
DATABASE_URI="postgresql://user:pass@localhost:5432/exordos_vpn" tox -e py312-functional

# Linting
tox -e ruff-check
tox -e mypy

# Coverage
tox -e begin,py312,end
```

## CLI Commands

The CLI uses `click` for command-line parsing and `oslo.config` for configuration file parsing.

Global options:

```bash
--config-file TEXT     Path to the configuration file
--config-dir TEXT      Directory for config and template files [default: /etc/exordos_vpn]
--format [table|json] Output format [default: table]
```

### Account

| Command | Description |
|---|---|
| `account-create <user_id> [--name NAME] [--pin-length N] [--access-type ALL\|RESTRICTED] [--tags TAGS] [--network NAME\|UUID] [--disable-pbin]` | Create account with PIN, OTP, cert (if configured), and network access rules |
| `account-list [--user-id UID]` | List accounts |
| `account-disable <account>` | Disable account |
| `account-generate-config <account> [--otp-uuid UUID] [--disable-pbin]` | Generate .ovpn config |
| `account-reset <account> [--pin-length N] [--otp-uuid UUID] [--disable-pbin]` | Reset PIN and OTP (with confirmation) |
| `account-reset-pin <account> [--pin-length N] [--disable-pbin]` | Reset PIN only, sends new PIN to PrivateBin |
| `account-set-otp <account> [--otp-uuid UUID]` | Replace OTP device for account |

> **`account-create` defaults to `--access-type RESTRICTED`** — new accounts can only reach services matching their tags. Use `--access-type ALL` to grant unrestricted network access.

### Network

| Command | Description |
|---|---|
| `network-create <name> --subnets SUBNETS [--description TEXT]` | Create a named VPN network (subnet pool) |
| `network-list` | List all VPN networks |
| `network-add-subnet <network> <subnets>` | Add subnets to a network (name or UUID) |
| `network-remove-subnet <network> <subnets>` | Remove subnets from a network |
| `network-delete <network>` | Delete a network (only if no accounts assigned) |

### Network Access

| Command | Description |
|---|---|
| `account-network-show <account>` | Show network access rules |
| `account-network-reset <account> [--access-type TYPE] [--tags TAGS]` | Full overwrite access type and tags |
| `account-network-add-tag <account> <tags>` | Add network access tags |
| `account-network-remove-tag <account> <tags>` | Remove network access tags |

### OTP

One OTP device is shared across all accounts of the same `user_id`.

| Command | Description |
|---|---|
| `otp-add <user_id> [--name NAME] [--disable-pbin]` | Add OTP device for user (links to all active accounts) |
| `otp-list <user_id>` | List OTP devices for user (with linked accounts) |
| `otp-remove <uuid>` | Disable OTP device |

### Service

| Command | Description |
|---|---|
| `service-create <name> --subnets SUBNETS [--tags TAGS] [--description TEXT] [--kinds KINDS]` | Create service |
| `service-list` | List services |
| `service-reset <uuid> [--name NAME] [--subnets SUBNETS] [--tags TAGS] [--description TEXT] [--kinds KINDS]` | Overwrite service fields |
| `service-add-subnet <uuid> <subnets>` | Add subnets |
| `service-remove-subnet <uuid> <subnets>` | Remove subnets |
| `service-add-tag <uuid> <tags>` | Add tags |
| `service-remove-tag <uuid> <tags>` | Remove tags |
| `service-add-kind <uuid> <kinds>` | Add firewall kinds |
| `service-remove-kind <uuid> <kinds>` | Remove firewall kinds |
| `service-delete <uuid>` | Delete service |

### PrivateBin Delivery

Commands marked with 📋 send credentials to PrivateBin (if `privatebin-endpoint` is configured and `--disable-pbin` is not set):

| Command | Delivers to client |
|---|---|
| 📋 `account-create` | Credentials text (login, PIN, OTP QR/URI if new) + .ovpn config file |
| 📋 `account-reset` | Credentials text (login, new PIN, new OTP QR/URI) + .ovpn config file |
| 📋 `account-reset-pin` | `New pin for <account_name>: <pin>` |
| 📋 `account-generate-config` | .ovpn config file |
| 📋 `otp-add` | OTP QR code (PNG embedded in markdown) |

When `show-credentials=false` (default), sensitive data (PIN, OTP secret, QR code) is **not** printed to the console — only sent via PrivateBin link.

### Configuration

Key config options (in `[common]` section):

| Option | Default | Description |
|---|---|---|
| `show-credentials` | `false` | Print PIN/OTP to console; when disabled, credentials go to PrivateBin only |
| `generate-certs` | `true` | Auto-generate certificates for new accounts |
| `privatebin-endpoint` | `""` | PrivateBin URL for sending credentials |

## Services

### User API (`exordos-vpn-user-api`)

REST API server with JWT-based authentication via IAM integration.

```bash
exordos-vpn-user-api --config-file /etc/exordos_vpn/user_api.conf
```

### Server Agent (`exordos-vpn-server-agent`)

Runs on VPN servers. Polls the database for config changes and manages OpenVPN configurations and iptables firewall rules.

```bash
exordos-vpn-server-agent --config-file /etc/exordos_vpn/server_agent.conf
```

Key options:
- `openvpn_config_dir` - Path to OpenVPN config files (default: `/etc/openvpn`)
- `openvpn_subnet_cidr` - VPN subnet in CIDR notation
- `firewall_enabled` - Enable iptables-based access control (default: `true`)
- `firewall_chain_prefix` - Prefix for iptables chain names (default: `exordos_vpn`)
- `firewall_global_whitelist` - Comma-separated CIDR blocks globally allowed

### Scheduler (`exordos-vpn-scheduler`)

Background service that cleans up unused address offsets from disabled certificates.

```bash
exordos-vpn-scheduler --config-file /etc/exordos_vpn/scheduler.conf
```

### Bootstrap (`exordos-vpn-bootstrap`)

Initialize IAM organization, project, roles, and permissions.

```bash
exordos-vpn-bootstrap --login admin --password admin --endpoint http://localhost:11010/v1/
```

## Server Config Recommendations

### OpenVPN

- Use OpenVPN-DCO kernel module for kernel 6.16+ and OpenVPN 2.7 (old DKMS-based DCO has [stability problems](https://github.com/OpenVPN/ovpn-dco/issues/56))
- DCO doesn't support mssfix, so set MTU explicitly:
  ```
  tun-mtu 1380
  ```
  **1380** bytes is a sweet spot; larger values may cause issues with mobile hotspots.
- **TCP** is *recommended* by default. Use **UDP** only when you can control clients and debug issues. UDP has drawbacks: it can't check connectivity easily, and may show disruptions instead of explicit disconnections on timeouts or when multiple machines connect with the same certificate.

### Client specifics and recommendations

#### Common
- See [exordos_vpn/common/ovpn_config.py](exordos_vpn/common/ovpn_config.py) for the config generation logic
- Use `key-direction 1` with inline `tls-auth` block instead of `tls-auth 1 inline`
- **Recommended**: Don't push `DOMAIN-SEARCH` records. Use private DNS for everything. Clients without `DOMAIN-SEARCH` support may ignore all DNS pushes.

#### Windows

- **OpenVPN Connect** (proprietary)
  - Doesn't support `inline` keyword; use file containers with specified names
  - Can't use split-DNS; uses pushed DNS for everything
  - **WARNING**: If any `DOMAIN-SEARCH` option is pushed, the client will ignore all pushed DNS. Avoid pushing `DOMAIN-SEARCH` or add `pull-filter ignore "dhcp-option DOMAIN-SEARCH"`.

- **OpenVPN community** (**recommended**)
  - Can't use split-DNS; uses pushed DNS for everything

- **Pritunl**
  - Uses old community client; works nearly the same

#### macOS

- **Tunnelblick**
  - Can't use split-DNS; uses pushed DNS for everything

#### Linux

- **OpenVPN from console**
  - Doesn't set DNS on connect automatically. Use `openvpn-systemd-resolved` or add to config:
    ```
    up /etc/openvpn/update-systemd-resolved
    down /etc/openvpn/update-systemd-resolved
    ```

- **OpenVPN KDE plugin** (**recommended**)
  - May use split-DNS if `systemd-resolved` installed appropriately

- **OpenVPN GNOME plugin**
  - Can use split-DNS, but can't use pushed DNS if `DOMAIN-SEARCH` is empty
  - If DNS problems: set VPN DNS explicitly (**recommended**) or add private domains to local split-DNS

#### iOS

- **OpenVPN Connect** (**recommended**)
  - Can't use split-DNS; uses pushed DNS for everything

#### Android

- **OpenVPN Connect** (**recommended**)
  - Can't use split-DNS; uses pushed DNS for everything

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────┐
│  Operator    │────>│  User API    │────>│   IAM     │
│  CLI         │     │  (Bjoern)    │     │           │
└─────────────┘     └──────┬───────┘     └───────────┘
                           │
                    ┌──────▼───────┐
                    │   PostgreSQL │
                    └──────┬───────┘
                           │
              ┌────────────┼
              │            │
       ┌──────▼───┐ ┌─────▼────┐
       │ Server    │ │ Scheduler│
       │ Agent     │ │          │
       └──────────┘ └──────────┘
```
