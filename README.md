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

### Account Management

```bash
# Create new account with auto-generated PIN and OTP
$ exordos-vpn-cli account-create user1 --account-name mobile

# List accounts (filter by user_id)
$ exordos-vpn-cli account-list --user-id user1

# Disable account
$ exordos-vpn-cli account-disable <account-uuid-or-name>

# Generate OpenVPN config for account
$ exordos-vpn-cli account-generate-config <account-uuid-or-name> --otp-uuid <otp-uuid>
```

### Certificate Management

```bash
# List certificates (filter by user_id)
$ exordos-vpn-cli cert-list --user-id user1
```

### OTP (Two-Factor Authentication)

```bash
# Add new OTP device
$ exordos-vpn-cli otp-add <account-uuid-or-name> --name "Phone"

# List OTP devices
$ exordos-vpn-cli otp-list <account-uuid-or-name>

# Remove (disable) OTP device
$ exordos-vpn-cli otp-remove <device-uuid>
```

### Service Management

```bash
# Create new service
$ exordos-vpn-cli service-create myservice \
    --subnets "10.0.0.0/8,172.16.0.0/12" \
    --tags "finance,engineering" \
    --kinds "any,tcp:80-443,udp:53"

# List services
$ exordos-vpn-cli service-list

# Delete service
$ exordos-vpn-cli service-delete <service-uuid>
```

### Network Access Control

```bash
# Set account network access type
$ exordos-vpn-cli account-set-network-access <account-uuid-or-name> \
    --access-type RESTRICTED --tags "finance,engineering"

# Grant full access
$ exordos-vpn-cli account-set-network-access <account-uuid-or-name> \
    --access-type ALL
```

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
