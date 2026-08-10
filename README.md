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
| `account-create <user_id> [--name NAME] [--pin-length N] [--access-type ALL\|RESTRICTED] [--tags TAGS] [--departments DEPTS] [--network NAME\|UUID] [--disable-pbin] [--no-otp]` | Create account with PIN, OTP, cert (if configured), and network access rules |
| `account-list [--user-id UID] [--full]` | List accounts (`--full` adds departments and effective tags) |
| `account-show <account>` | Show full account info (auth, network, IP, tags, departments, effective tags, OTP devices, certs) |
| `account-disable <account>` | Disable account (drops the cached login; the OTP device and certificate stay valid — use `account-reset` if credentials may be compromised) |
| `account-enable <account>` | Re-enable a disabled account, keeping its client IP; refused once the scheduler has freed the account's address offset |
| `account-generate-config <account> [--otp-uuid UUID] [--disable-pbin]` | Generate .ovpn config |
| `account-reset <account> [--pin-length N] [--disable-pbin]` | Reset PIN and OTP (with confirmation; PIN only if OTP is off) |
| `account-reset-pin <account> [--pin-length N] [--disable-pbin]` | Reset PIN only, sends new PIN to PrivateBin |
| `account-set-otp <account> [--otp-uuid UUID]` | Replace OTP device for account |
| `account-otp-required <account> <on\|off>` | Toggle OTP requirement: with `off` the whole VPN password is the PIN (no OTP code, no OTP device needed) |

> **`account-create` defaults to `--access-type RESTRICTED`** — new accounts can only reach services matching their tags. Use `--access-type ALL` to grant unrestricted network access.

### Network

| Command | Description |
|---|---|
| `network-create <name> --subnets SUBNETS [--description TEXT]` | Create a named VPN network (subnet pool) |
| `network-list` | List all VPN networks |
| `network-add-subnet <network> <subnets>` | Add subnets to a network (name or UUID) |
| `network-remove-subnet <network> <subnets>` | Remove subnets from a network |
| `network-delete <network>` | Delete a network (only if no accounts assigned) |

### Address history

Each account owns an `address_offset` within its network, which resolves to a concrete client IP. When an account stays disabled long enough the [scheduler](#scheduler-exordos-vpn-scheduler) frees its offset and a later account may reuse it — so the same IP belongs to different accounts over time. Every ownership span is recorded in an append-only history (account/network identity is snapshotted, so the trail survives account or network deletion). Both commands honor `--format json` for export.

| Command | Description |
|---|---|
| `address-list [--network NAME\|UUID] [--active] [--history]` | One row per IP ever allocated: current owner (open span), total owner count, first/last activity. `--active` shows only IPs with a current owner; `--history` expands each IP into its full ownership history (every span, grouped by IP) |
| `address-history [--ip IP] [--network NAME\|UUID] [--user-id UID] [--account NAME\|UUID] [--active] [--sort offset\|time]` | Full ownership timeline: who held which IP, from/until when, and why it was released. Grouped by network + offset by default (chronological within each offset); `--sort time` for a purely chronological view. `--active` shows only currently-held spans |

```bash
# Who has ever held 10.8.0.2, in order, with dates
exordos-vpn-cli address-history --ip 10.8.0.2
# Export the whole allocation history as JSON
exordos-vpn-cli --format json address-history > allocations.json
```

### Network Access

| Command | Description |
|---|---|
| `account-network-reset <account> [--access-type TYPE] [--tags TAGS]` | Full overwrite access type and tags |
| `account-network-add-tag <account> <tags>` | Add network access tags |
| `account-network-remove-tag <account> <tags>` | Remove network access tags |

### Departments

Org-structure tree for granting access per department instead of per account. A department carries `network_access_tags`; member accounts get those tags — plus the tags of all ancestor departments — merged into their own for Service matching. Everything else (Service tags, firewall, routing, CCD pushes) works exactly as with account-level tags. `network_access_type` (ALL/RESTRICTED) stays per-account; personal account tags remain as an additive exception mechanism.

| Command | Description |
|---|---|
| `department-create <name> [--parent P] [--tags TAGS] [--description TEXT]` | Create department |
| `department-list [--tree]` | List departments with own and effective (inherited) tags; `--tree` draws the hierarchy (nested JSON with `--format json`) |
| `department-set-parent <department> <parent>` | Move under another parent (`""` makes it a root; cycles are refused) |
| `department-add-tag <department> <tags>` | Add network access tags |
| `department-remove-tag <department> <tags>` | Remove network access tags |
| `department-delete <department>` | Delete (refused while it has children or members) |
| `account-department-add <account> <departments>` | Add account to departments |
| `account-department-remove <account> <departments>` | Remove account from departments |

Example:

```bash
exordos-vpn-cli department-create org --tags vpn-basic
exordos-vpn-cli department-create engineering --parent org --tags git
exordos-vpn-cli account-create alice --departments engineering
# alice now matches services tagged vpn-basic or git
```

### OTP

One OTP device is shared across all accounts of the same `user_id`.

OTP can be disabled per account (`account-create --no-otp` / `account-otp-required <account> off`): login then takes the whole password as the PIN and needs no OTP device at all (e.g. service accounts). This drops password auth to a single factor — prefer `cert_and_password` auth for such accounts so the client TLS certificate compensates.

| Command | Description |
|---|---|
| `otp-add <user_id> [--name NAME] [--disable-pbin]` | Add OTP device for user (links to all active accounts) |
| `otp-list <user_id>` | List OTP devices for user (with linked accounts) |
| `otp-remove <uuid>` | Disable OTP device |

### Service

A service needs at least one of `--subnets`/`--domains`. See [External resources / routing](#external-resources--routing) for `--domains`/`--nexthop`. `<service>` accepts a name or a UUID.

| Command | Description |
|---|---|
| `service-create <name> [--subnets SUBNETS] [--domains DOMAINS] [--nexthop IP] [--tags TAGS] [--description TEXT] [--kinds KINDS]` | Create service |
| `service-list` | List services |
| `service-reset <service> [--name NAME] [--subnets SUBNETS] [--domains DOMAINS] [--nexthop IP] [--tags TAGS] [--description TEXT] [--kinds KINDS]` | Overwrite service fields (`--nexthop ""` clears it) |
| `service-set-nexthop <service> <nexthop>` | Route the service via a nexthop gateway IP (`""` clears it back to normal routing) |
| `service-add-subnet <service> <subnets>` | Add subnets |
| `service-remove-subnet <service> <subnets>` | Remove subnets |
| `service-add-domain <service> <domains>` | Add domains |
| `service-remove-domain <service> <domains>` | Remove domains |
| `service-add-tag <service> <tags>` | Add tags |
| `service-remove-tag <service> <tags>` | Remove tags |
| `service-add-kind <service> <kinds>` | Add firewall kinds |
| `service-remove-kind <service> <kinds>` | Remove firewall kinds |
| `service-delete <service>` | Delete service |

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
- `routing_enabled` - Enable nexthop-based routing for services with `nexthop` set (default: `false`); see [External resources / routing](#external-resources--routing)
- `routing_proto_id` - rtnetlink `proto` value tagging routes owned by this agent (default: `172`)
- `dns_resolve_min_interval_seconds` - Floor between re-resolutions of a domain's A records, regardless of TTL (default: `30`)
- `dns_resolvers` - Comma-separated DNS server IPs used to resolve `Service.domains` (default: system resolver, i.e. `/etc/resolv.conf`); for domain-based routing, point the OpenVPN server config's global `push "dhcp-option DNS ..."` at the same resolver, see below
- `private_networks` - Comma-separated CIDR blocks the OpenVPN server config already pushes to every client (e.g. `10.0.0.0/8,172.16.0.0/12`); service destinations inside them are skipped when generating per-account CCD route pushes (default: empty — every matched destination is pushed)

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

## External resources / routing

By default a `Service` only controls *access* (which tagged accounts may reach which `subnets`/`domains`); traffic is forwarded via the VPN gateway's normal default route. Setting `nexthop` on a `Service` (a plain gateway IP of a separate proxy/router box, e.g. an xray client egressing from another region) makes the server agent additionally route that service's destinations via that nexthop instead — so different tags/accounts can be sent out through different egress paths for the same firewall model, with no new CP entity.

```bash
exordos-vpn-cli service-create git-via-eu --domains github.com,api.github.com --nexthop 203.0.113.10 --tags git
exordos-vpn-cli service-set-nexthop existing-svc 203.0.113.10   # or add/change it later ("" clears)
exordos-vpn-cli account-reset alice --network-access-tags git
```

### Split-tunnel: getting client traffic into the tunnel at all

exordos_vpn does **not** use `redirect-gateway` (full-tunnel) — clients only route into the VPN whatever OpenVPN explicitly pushes them. A tag-based firewall ACCEPT rule alone is not enough for a `RESTRICTED` account to reach a service: unless the client's own OS routing table also points that destination at the tun interface, matching traffic never enters the tunnel in the first place and just goes out the client's normal internet connection.

To make this work, the server agent pushes per-account routes via [client-config-dir](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-4/) (`ccd/<account_name>`, alongside the existing `ifconfig-push`): for every `Service` the account may reach (tag match for `RESTRICTED` accounts), one `push "route <net> <mask>"` per static subnet and one per currently-resolved domain IP (`/32`). Destinations contained in the configured `private_networks` are skipped — those CIDRs are what the OpenVPN server config already pushes to every client, so a per-account push would be a duplicate; set this option in any real deployment (with it empty, internal services' subnets get redundantly re-pushed per account).

DNS is *not* pushed per-account: clients get their resolver from the OpenVPN server config's global `push "dhcp-option DNS ..."` (they need one for everything, not just domain services). Domain-based routing only works if the client resolves a domain to the *same* IP(s) the server-side agent resolved and pushed routes for — ensure the global dhcp-option and the agent's `dns_resolvers` point at the same resolver.

A CCD file is rebuilt whenever the account itself changes, but also whenever *any* Service it might match changes, or a matched domain's resolved IPs change — not just on the account's own `updated_at`, since none of those touch the account row. **A route change only reaches an already-connected client on its next reconnect** (OpenVPN doesn't support pushing new routes into a live session); this is the same class of staleness tradeoff as the DNS TTL caveat below.

`network_access_type == "ALL"` accounts get routes for **every** `Service` outside `private_networks` (regardless of tags): their firewall grant is a blanket ACCEPT, but by default the client only tunnels the pushed private routes — so the services' external destinations are what gets pushed. Full-tunnel `redirect-gateway` is not implemented.

### Data-plane mechanics (nexthop routing)

The above makes traffic reach the VPN gateway; nexthop routing (below) then controls what the gateway does with it once it arrives. Requires `routing_enabled = true`:

1. **Domains → ipset.** For services with `domains`, a background DNS step (part of the same agent loop, throttled per-domain by the resolved TTL, floored at `dns_resolve_min_interval_seconds`) resolves A records and maintains one `ipset` per service. This also keeps the firewall rule count bounded: instead of one literal `-d <ip>` rule per resolved address, the ACCEPT rule matches `-m set --match-set <name> dst`.
2. **Routing.** For services with `nexthop`, the agent installs one route per static `subnets` entry or per currently-resolved domain IP (`ip route replace <dst> via <nexthop> proto <routing_proto_id>`; `ip route` can't match an ipset, so domain-routed destinations are host routes). Routes are tagged with a private rtnetlink `proto` id so reconciliation never touches unrelated host routes, and are reconciled independently of the ACL/firewall rules — **routing is destination-only, not per-account**: once any account is allowed to reach a destination, the route benefits all traffic to it from this box, the same blast-radius shape as `firewall_global_whitelist`.

The nexthop must be **directly reachable from the VPN gateway** (an on-link route, no intermediate gateway) — that's a kernel requirement for `via`. The agent verifies this upfront (`ip route get`) and skips routes via a nexthop that doesn't qualify, with a warning in the log; ipset/route failures in general are logged and retried, never blocking firewall/CCD reconciliation.

New system dependency: `ipset` must be installed on the VPN gateway host (alongside the already-required `iptables`).

**Caveat — CDN / shared-IP domains.** DNS-pinning a domain to an ipset works well for services with stable, dedicated IPs. It's a poor fit for domains fronted by a shared-IP CDN (Cloudflare, Akamai, etc.): the resolved IP can be shared by thousands of unrelated domains (so a route/ACL keyed on that IP is broader than intended), and can rotate faster than is practical to track. Prefer this feature for domains with dedicated IPs; for CDN-fronted domains, routing all of the relevant tag's traffic through the nexthop (rather than DNS-pinning specific domains) and letting the nexthop's own SNI/domain-aware routing (e.g. xray) make the per-domain decision is more robust.

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
