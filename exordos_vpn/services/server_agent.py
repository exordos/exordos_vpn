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

import datetime
import logging
import os
import subprocess

import dns.exception
import dns.resolver
from gcl_looper.services import basic
import netaddr
from restalchemy.common import contexts
from restalchemy.dm import filters as dm_filters
from restalchemy.dm import types

from exordos_vpn.dm import models

LOG = logging.getLogger(__name__)

IPTABLES_SAVE_BIN = "iptables-save"
IPTABLES_BIN_PATH = "/usr/sbin/iptables"
FIREWALL_TABLE = "filter"

IPSET_BIN_PATH = "/usr/sbin/ipset"
IP_BIN_PATH = "/usr/sbin/ip"
IPSET_NAME_PREFIX = "exvpn_svc_"
DEFAULT_DNS_TTL_FLOOR_SECONDS = 30


def _host_cidr(ip):
    """Return a host IP in /32 CIDR notation as iptables normalizes it."""
    return f"{ip}/32"


def _ipset_name(service):
    """Deterministic ipset name for a domain-based service (max 31 chars)."""
    return f"{IPSET_NAME_PREFIX}{str(service.uuid).replace('-', '')[:16]}"


def _build_kind_rules(chain_name, client_ip, dst_clause, kind):
    """Build iptables ACCEPT rule for a single kind.

    dst_clause is either "-d <cidr>" (static subnet) or
    "-m set --match-set <name> dst" (domain-based service, resolved via the
    DNS agent into an ipset).

    For 'any' kind: unrestricted access to the destination.
    For 'tcp'/'udp' kind: protocol-specific access with port range.

    Returns:
        set of rule strings (may contain multiple rules for port ranges)
    """
    src = _host_cidr(client_ip)
    if kind.KIND == "any":
        return {f"-A {chain_name} -s {src} {dst_clause} -j ACCEPT"}

    protocol = kind.KIND
    min_port = kind.min_port
    max_port = kind.max_port
    rules = set()

    if min_port == 1 and max_port == 65535:
        rules.add(f"-A {chain_name} -s {src} {dst_clause} -p {protocol} -j ACCEPT")
    elif min_port == max_port:
        rules.add(
            f"-A {chain_name} -s {src} {dst_clause} "
            f"-p {protocol} -m {protocol} --dport {min_port} -j ACCEPT"
        )
    else:
        rules.add(
            f"-A {chain_name} -s {src} {dst_clause} "
            f"-p {protocol} -m {protocol} --dport {min_port}:{max_port} -j ACCEPT"
        )
    return rules


def _build_chain_rules(
    chain_name, vpn_subnet, vpn_server_ip, firewall_whitelist, accounts, services
):
    """Build desired ACCEPT and DROP rules for a chain.

    Returns:
        dict with "accept" (set of ACCEPT rule strings) and "drop" (DROP rule string)
    """
    accept_rules = set()

    # Allow VPN client to reach VPN server (essential for management)
    accept_rules.add(
        f"-A {chain_name} -s {vpn_subnet} -d {_host_cidr(vpn_server_ip)} -j ACCEPT"
    )

    for account in accounts:
        if account.status == "DISABLED" or not account.address_offset:
            continue
        try:
            client_ip, _ = account.network.ip_for_offset(account.address_offset)
        except ValueError:
            LOG.warning(
                "Cannot resolve IP for account %r, skipping firewall rules",
                account.account_name,
            )
            continue
        src = _host_cidr(client_ip)
        if account.network_access_type == "ALL":
            accept_rules.add(f"-A {chain_name} -s {src} -j ACCEPT")
        else:
            account_tags = set(account.network_access_tags or [])
            for service in services:
                service_tags = set(service.tags or [])
                if not (account_tags & service_tags):
                    continue
                service_kinds = service.kinds
                dst_clauses = [f"-d {subnet}" for subnet in service.subnets]
                if service.domains:
                    dst_clauses.append(f"-m set --match-set {_ipset_name(service)} dst")
                if not service_kinds:
                    for dst_clause in dst_clauses:
                        accept_rules.add(
                            f"-A {chain_name} -s {src} {dst_clause} -j ACCEPT"
                        )
                else:
                    for dst_clause in dst_clauses:
                        for kind in service_kinds:
                            accept_rules.update(
                                _build_kind_rules(
                                    chain_name, client_ip, dst_clause, kind
                                )
                            )

    # Allow global whitelist CIDRs from VPN subnet
    for cidr in firewall_whitelist:
        accept_rules.add(f"-A {chain_name} -s {vpn_subnet} -d {cidr} -j ACCEPT")

    # Default deny for VPN subnet (always last)
    drop_rule = f"-A {chain_name} -s {vpn_subnet} -j DROP"

    return {"accept": accept_rules, "drop": drop_rule}


def _make_chain_name(prefix, version, subnet):
    """Generate a deterministic chain name from prefix config."""
    safe_subnet = str(subnet).replace("/", "_")
    return f"{prefix}_{version}_{safe_subnet}"


def _resolve_domain(domain, resolvers=None, timeout=5.0):
    """Resolve A records for domain via dnspython.

    resolvers, if given, is a list of DNS server IPs to query instead of
    the system resolver (/etc/resolv.conf) — e.g. to force resolution
    through a specific upstream rather than whatever the VPN gateway host
    happens to be configured with.

    Returns (ip_set, ttl_seconds), or None if resolution failed (caller
    should keep using the last-known-good answer, if any).
    """
    if resolvers:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = resolvers
    else:
        resolver = dns.resolver.get_default_resolver()
    try:
        answer = resolver.resolve(domain, "A", lifetime=timeout)
    except dns.exception.DNSException as e:
        LOG.warning("DNS resolution failed for %r: %s", domain, e)
        return None
    ips = {str(rdata) for rdata in answer}
    ttl = answer.rrset.ttl if answer.rrset is not None else 0
    return ips, ttl


def _parse_dns_resolvers(raw):
    """Parse the comma-separated dns_resolvers config value into a list of
    IP strings, skipping (and warning about) invalid entries."""
    resolvers = []
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            netaddr.IPAddress(entry)
        except (netaddr.AddrFormatError, ValueError) as e:
            LOG.warning("Invalid dns_resolvers entry %r: %s", entry, e)
            continue
        resolvers.append(entry)
    return resolvers


def _parse_private_networks(raw):
    """Parse the comma-separated private_networks config value into a list
    of netaddr.IPNetwork, skipping (and warning about) invalid entries."""
    networks = []
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(netaddr.IPNetwork(entry))
        except (netaddr.AddrFormatError, ValueError) as e:
            LOG.warning("Invalid private_networks entry %r: %s", entry, e)
    return networks


def _in_private_networks(dst, private_networks):
    """True if dst (an IPNetwork or IPAddress) is fully contained in one of
    private_networks — i.e. the OpenVPN server config already pushes a
    covering route for it and the client needs nothing extra."""
    return any(dst in net for net in private_networks)


def _normalize_dst(dst):
    """Ensure a route destination carries an explicit prefix length.

    `ip route show` prints host routes without a /32 (or /128) suffix, so
    reconciliation must normalize both sides before diffing.
    """
    if "/" in dst:
        return dst
    return f"{dst}/128" if ":" in dst else f"{dst}/32"


def _build_desired_routes(services, resolved_domains):
    """Build the desired {dst_cidr: nexthop_ip} mapping for routed services.

    Static `subnets` map directly; `domains` are routed as individual host
    routes for each currently-resolved IP (ip route can't match an ipset).
    """
    desired = {}
    for service in services:
        if not service.nexthop:
            continue
        nexthop = str(service.nexthop)
        for subnet in service.subnets:
            desired[str(subnet)] = nexthop
        for domain in service.domains:
            for ip in resolved_domains.get(str(domain), set()):
                desired[_normalize_dst(ip)] = nexthop
    return desired


def _account_matched_services(account, services):
    """Services this account may reach.

    Mirrors the same matching _build_chain_rules uses for the firewall
    ACCEPT rules, so a route is only ever pushed for a destination the
    firewall would actually let through: "ALL" accounts get a blanket
    ACCEPT there, so they match every service; RESTRICTED accounts match
    by tag intersection.
    """
    if account.network_access_type == "ALL":
        return list(services)
    account_tags = set(account.network_access_tags or [])
    return [s for s in services if account_tags & set(s.tags or [])]


def _build_ccd_push_lines(account, services, resolved_domains, private_networks):
    """Build `push "route ..."` lines for an account's CCD file.

    A tag-based ACCEPT rule in the firewall is not enough on its own in
    split-tunnel mode: unless the client's OS also has a route pointing
    the destination at the tun interface, matching traffic never enters
    the tunnel in the first place. This mirrors _account_matched_services
    to push exactly (and only) the routes each account's ACL grants.

    Destinations contained in `private_networks` (the CIDRs the OpenVPN
    server config already pushes to every client) are skipped: the client
    already tunnels them, a per-account push would be a duplicate. With
    the option unset every matched destination is pushed — harmlessly
    redundant for internal services, so set it in any real deployment.

    `network_access_type == "ALL"` accounts match *every* service: their
    firewall grant is a blanket ACCEPT, but the client still only tunnels
    what's pushed. Full-tunnel redirect-gateway is out of scope.

    DNS is deliberately NOT pushed here: clients get their resolver from
    the OpenVPN server config's global `push "dhcp-option DNS ..."` (they
    need one for anything to work at all, not just for domain services).
    Domain-based routing/ACL still requires the client to resolve to the
    same IPs the agent did — ensured by pointing `dns_resolvers` and the
    server config's global dhcp-option at the same resolver.
    """
    lines = []
    seen_routes = set()

    for service in _account_matched_services(account, services):
        for subnet in service.subnets:
            net = netaddr.IPNetwork(str(subnet))
            if _in_private_networks(net, private_networks):
                continue
            key = (str(net.network), str(net.netmask))
            if key not in seen_routes:
                seen_routes.add(key)
                lines.append(f'push "route {net.network} {net.netmask}"')

        for domain in service.domains:
            for ip in resolved_domains.get(str(domain), set()):
                if _in_private_networks(netaddr.IPAddress(ip), private_networks):
                    continue
                key = (ip, "255.255.255.255")
                if key not in seen_routes:
                    seen_routes.add(key)
                    lines.append(f'push "route {ip} 255.255.255.255"')

    return lines


class AgentService(basic.BasicService):
    def __init__(self, prefixes=None, **kwargs):
        self.prefixes = prefixes
        self._ctx = contexts.Context()
        self.last_processed_at = datetime.datetime.strptime(
            "2000-01-01T00:00:00.000000Z", types.OPENAPI_DATETIME_FMT
        )
        # lag to avoid race conditions
        self.lag = datetime.timedelta(seconds=30)
        # domain -> (ip_set, expires_at); populated by _reconcile_dns
        self._dns_cache = {}
        # last resolved{domain: ip_set} snapshot handed to process_instance,
        # so _iteration can detect "DNS changed" and force a full CCD rebuild
        self._last_resolved_for_ccd = None
        # last total Service row count, to detect deletions (see
        # _has_firewall_data_changed): an `updated_at >=` filter can never
        # match a row that's gone, so a deleted Service is otherwise
        # invisible and its ACCEPT rule/route/CCD entry would linger.
        self._last_service_count = None
        # nexthops already warned about as not-on-link, to log once
        # instead of every tick (see _filter_routable_services)
        self._warned_nexthops = set()
        super().__init__(**kwargs)

    def _iteration(self):
        iter_started = datetime.datetime.now(datetime.timezone.utc)

        # Domain resolution / ipsets / nexthop routes: this can't be gated
        # on "did DB data change" like firewall reconciliation below, since
        # a Service row can be untouched while its domains' resolved IPs
        # rotate (CDN/anycast). Cheap no-op on most ticks: DNS answers are
        # cached per-domain until their TTL expires, and ipset/route
        # reconciliation diff against current state before touching anything.
        services, resolved = [], {}
        if self.prefixes:
            services, resolved = self._reconcile_routing()

        resolved_changed = resolved != self._last_resolved_for_ccd
        self._last_resolved_for_ccd = resolved

        # Reconcile firewall with incremental data first
        firewall_data_changed = self._has_firewall_data_changed()
        if firewall_data_changed and self.prefixes:
            self._reconcile_firewall()

        # CCD (ifconfig-push + per-account `push route`/DNS lines):
        # incremental fetch of accounts updated since last cycle, unless a
        # Service changed (may add/remove routes for accounts whose own
        # row is untouched) or a domain's resolved IPs changed (same
        # reason) — in which case every CCD needs re-evaluating.
        full_ccd_rebuild = firewall_data_changed or resolved_changed
        with self._ctx.session_manager() as s:
            if full_ccd_rebuild:
                accounts = models.Account.objects.get_all(session=s)
            else:
                filters = {
                    "updated_at": dm_filters.GE(self.last_processed_at),
                }
                accounts = models.Account.objects.get_all(session=s, filters=filters)

        for name, conf in self.prefixes.items():
            self.process_instance(name, conf, accounts, services, resolved)

        # Update cursor after processing both CCD and firewall
        self.last_processed_at = iter_started - self.lag

    def _has_firewall_data_changed(self):
        """Check if any accounts or services changed since last reconciliation.

        Returns True if a full snapshot is needed for firewall reconciliation.

        `updated_at >=` catches inserts/updates but can never match a row
        that's been deleted, so a deleted Service (whose subnets/domains an
        account may still be ACCEPTed for) would otherwise never be
        detected as a change. Total Service count is tracked across calls
        to additionally catch deletions. Account deletions aren't tracked
        this way: an orphaned CCD/iptables entry for a deleted account is
        low-risk (its cert is gone too, so it can't reconnect), unlike a
        still-connected account keeping access via a deleted Service.
        """
        with self._ctx.session_manager() as s:
            filters = {
                "updated_at": dm_filters.GE(self.last_processed_at),
            }
            if models.Account.objects.count(session=s, filters=filters):
                return True
            if models.Service.objects.count(session=s, filters=filters):
                return True
            service_count = models.Service.objects.count(session=s)

        service_deleted = (
            self._last_service_count is not None
            and service_count != self._last_service_count
        )
        self._last_service_count = service_count
        return service_deleted

    def _routing_conf(self):
        """Routing/DNS options are host-wide (not per-openvpn-instance);
        take them from an arbitrary configured prefix (in practice there is
        usually exactly one)."""
        return next(iter(self.prefixes.values()), None)

    def _reconcile_routing(self):
        """Refresh DNS-resolved ipsets (always) and nexthop routes (if
        routing_enabled). See the comment in _iteration() for why this
        can't be gated on _has_firewall_data_changed().

        Always runs the full reconcile (not just when a service currently
        has domains/nexthop): a service losing its last domain or nexthop
        must still get its stale ipset/route cleaned up, and that only
        happens by diffing against the (now smaller) desired state.

        Returns (services, resolved) so the caller can reuse the same
        snapshot for CCD route-push generation without a second DNS pass.
        """
        with self._ctx.session_manager() as s:
            services = models.Service.objects.get_all(session=s)

        conf = self._routing_conf()
        min_interval = getattr(
            conf, "dns_resolve_min_interval_seconds", DEFAULT_DNS_TTL_FLOOR_SECONDS
        )
        routing_enabled = getattr(conf, "routing_enabled", False)
        routing_proto_id = getattr(conf, "routing_proto_id", 172)
        resolvers = _parse_dns_resolvers(getattr(conf, "dns_resolvers", ""))

        resolved = self._reconcile_dns(services, min_interval, resolvers)

        # ipset/route syscall failures must not escape: they'd abort the
        # whole iteration, blocking firewall/CCD reconciliation (including
        # access revocations) until the failure clears. Log and retry next
        # tick instead.
        try:
            self._reconcile_ipsets(services, resolved)
        except Exception:
            LOG.exception("ipset reconciliation failed, will retry")

        if routing_enabled:
            try:
                routed = self._filter_routable_services(services)
                desired_routes = _build_desired_routes(routed, resolved)
                self._reconcile_routes(desired_routes, routing_proto_id)
            except Exception:
                LOG.exception("route reconciliation failed, will retry")

        return services, resolved

    def _filter_routable_services(self, services):
        """Drop services whose nexthop can't actually be used as a gateway.

        `ip route replace <dst> via <nexthop>` requires the nexthop to be
        directly reachable (an on-link route, no intermediate gateway);
        a nexthop that isn't would otherwise fail the whole route
        reconcile with "Nexthop has invalid gateway" on every tick.
        Checked upfront per unique nexthop via `ip route get`; invalid
        ones are skipped with a warning (once, until they change state).
        """
        validity = {}
        for service in services:
            if not service.nexthop:
                continue
            nexthop = str(service.nexthop)
            if nexthop not in validity:
                validity[nexthop] = self._nexthop_on_link(nexthop)

        for nexthop, valid in validity.items():
            if valid:
                self._warned_nexthops.discard(nexthop)
            elif nexthop not in self._warned_nexthops:
                self._warned_nexthops.add(nexthop)
                LOG.warning(
                    "Nexthop %s is not directly reachable (no on-link "
                    "route); skipping routes via it",
                    nexthop,
                )

        return [
            s for s in services if not s.nexthop or validity.get(str(s.nexthop), False)
        ]

    def _nexthop_on_link(self, nexthop):
        """True if nexthop is directly reachable (usable as a route gateway)."""
        try:
            out = self._run_ip("route", "get", nexthop)
        except RuntimeError:
            return False
        first_line = out.splitlines()[0] if out.splitlines() else ""
        return " via " not in f" {first_line} "

    def _reconcile_dns(self, services, min_interval_seconds, resolvers=None):
        """Resolve A records for every Service.domains, respecting each
        domain's own TTL floored at min_interval_seconds so short-TTL
        domains can't force a resolve on every tick.

        resolvers, if given, is a list of DNS server IPs to query instead
        of the system resolver (see dns_resolvers config option).

        Returns dict[domain -> set of ip strings].
        """
        domains = set()
        for service in services:
            domains.update(str(d) for d in service.domains)

        now = datetime.datetime.now(datetime.timezone.utc)
        resolved = {}
        for domain in domains:
            cached = self._dns_cache.get(domain)
            if cached is not None and cached[1] > now:
                resolved[domain] = cached[0]
                continue

            result = _resolve_domain(domain, resolvers=resolvers)
            if result is None:
                if cached is not None:
                    resolved[domain] = cached[0]
                continue

            ips, ttl = result
            expires_at = now + datetime.timedelta(
                seconds=max(ttl, min_interval_seconds)
            )
            self._dns_cache[domain] = (ips, expires_at)
            resolved[domain] = ips

        for stale_domain in set(self._dns_cache) - domains:
            del self._dns_cache[stale_domain]

        return resolved

    def _run_ipset(self, *args):
        """Run an ipset command, raising on any failure."""
        result = subprocess.run(
            [IPSET_BIN_PATH] + list(args),
            capture_output=True,
            text=True,
            timeout=10,
        )
        LOG.debug("_run_ipset: %r", args)
        if result.returncode != 0:
            raise RuntimeError(
                f"ipset failed: {' '.join(args)}\n"
                f"rc={result.returncode} stderr={result.stderr}\n"
                f"stdout={result.stdout}"
            )
        return result.stdout

    def _list_managed_ipsets(self):
        """List existing ipsets managed by this agent (by name prefix)."""
        out = self._run_ipset("list", "-name")
        return {
            line.strip()
            for line in out.splitlines()
            if line.strip().startswith(IPSET_NAME_PREFIX)
        }

    def _ipset_members(self, name):
        """Current member IPs of an ipset."""
        out = self._run_ipset("list", name, "-output", "plain")
        members = set()
        in_members = False
        for line in out.splitlines():
            if line.startswith("Members:"):
                in_members = True
                continue
            if in_members and line.strip():
                members.add(line.strip())
        return members

    def _reconcile_ipset(self, name, desired_ips, exists):
        """Atomically swap an ipset's membership to desired_ips.

        Uses a temp-set + swap so there's no window with an empty/partial
        set visible to iptables (same fail-safe spirit as
        _reconcile_chain's DROP-first ordering).
        """
        current = self._ipset_members(name) if exists else set()
        if exists and current == desired_ips:
            return

        tmp_name = f"{name}_tmp"
        self._run_ipset("create", tmp_name, "hash:ip", "-exist")
        self._run_ipset("flush", tmp_name)
        for ip in desired_ips:
            self._run_ipset("add", tmp_name, ip)
        if not exists:
            self._run_ipset("create", name, "hash:ip", "-exist")
        self._run_ipset("swap", tmp_name, name)
        self._run_ipset("destroy", tmp_name)

    def _reconcile_ipsets(self, services, resolved_domains):
        """Ensure one ipset per domain-based Service, and remove stale ones
        for services that no longer have domains (or were deleted)."""
        managed = self._list_managed_ipsets()
        desired_names = set()

        for service in services:
            if not service.domains:
                continue
            name = _ipset_name(service)
            desired_names.add(name)
            desired_ips = set()
            for domain in service.domains:
                desired_ips.update(resolved_domains.get(str(domain), set()))
            self._reconcile_ipset(name, desired_ips, exists=name in managed)

        for stale in managed - desired_names:
            try:
                self._run_ipset("destroy", stale)
            except RuntimeError:
                LOG.warning(
                    "ipset %s still in use, will retry next iteration",
                    stale,
                    exc_info=True,
                )

    def _run_ip(self, *args):
        """Run an `ip` command, raising on any failure."""
        result = subprocess.run(
            [IP_BIN_PATH] + list(args),
            capture_output=True,
            text=True,
            timeout=10,
        )
        LOG.debug("_run_ip: %r", args)
        if result.returncode != 0:
            raise RuntimeError(
                f"ip command failed: {' '.join(args)}\n"
                f"rc={result.returncode} stderr={result.stderr}\n"
                f"stdout={result.stdout}"
            )
        return result.stdout

    def _get_current_routes(self, proto_id):
        """Current {dst: nexthop} routes owned by this agent (tagged with
        proto_id), so reconciliation never touches unrelated host routes."""
        out = self._run_ip("route", "show", "proto", str(proto_id))
        routes = {}
        for line in out.splitlines():
            parts = line.split()
            if not parts or parts[0] == "default":
                continue
            dst = _normalize_dst(parts[0])
            if "via" in parts:
                routes[dst] = parts[parts.index("via") + 1]
        return routes

    def _reconcile_routes(self, desired_routes, proto_id):
        """Diff-based route reconciliation, scoped to proto_id."""
        current = self._get_current_routes(proto_id)
        if current == desired_routes:
            return

        for dst, nexthop in desired_routes.items():
            if current.get(dst) != nexthop:
                self._run_ip(
                    "route",
                    "replace",
                    dst,
                    "via",
                    nexthop,
                    "proto",
                    str(proto_id),
                )

        for dst in set(current) - set(desired_routes):
            self._run_ip("route", "del", dst, "proto", str(proto_id))

    def _reconcile_firewall(self):
        """Reconcile iptables state against desired configuration.

        Strategy:
        1. Load full data snapshot from database
        2. Build desired state by iterating prefixes
        3. Check current state per-chain using iptables -S/-C
        4. Apply changes: remove stale → create missing → reconcile → FORWARD
        """
        # Load full data snapshot
        with self._ctx.session_manager() as s:
            accounts = models.Account.objects.get_all(session=s)
            services = models.Service.objects.get_all(session=s)

        # Build desired chains from all prefixes
        desired_chains = {}
        chain_to_subnet = {}
        chain_prefixes = set()
        for name, conf in self.prefixes.items():
            chain_prefix = getattr(conf, "firewall_chain_prefix", "exordos_vpn")
            chain_prefixes.add(chain_prefix)
            fw_enabled = getattr(conf, "firewall_enabled", False)
            if not fw_enabled:
                continue
            vpn_subnet_raw = conf.openvpn_subnet_cidr
            vpn_ip_part = vpn_subnet_raw.split("/")[0]
            vpn_subnet = netaddr.IPNetwork(vpn_subnet_raw).cidr
            fw_whitelist_raw = getattr(conf, "firewall_global_whitelist", "")
            firewall_whitelist = []
            if fw_whitelist_raw:
                for entry in fw_whitelist_raw.split(","):
                    entry = entry.strip()
                    if not entry:
                        continue
                    try:
                        netaddr.IPNetwork(entry)
                    except (netaddr.AddrFormatError, ValueError) as e:
                        LOG.warning("Invalid whitelist CIDR '%s': %s", entry, e)
                        continue
                    firewall_whitelist.append(entry)
            chain_name = _make_chain_name(chain_prefix, name, vpn_subnet)
            desired_chains[chain_name] = _build_chain_rules(
                chain_name,
                vpn_subnet,
                vpn_ip_part,
                firewall_whitelist,
                accounts,
                services,
            )
            chain_to_subnet[chain_name] = str(vpn_subnet)

        # Find stale managed chains
        managed_chains = self._list_managed_chains(chain_prefixes)
        desired_names = set(desired_chains)

        # Create/reconcile each desired chain
        for chain_name in desired_names:
            if chain_name not in managed_chains:
                self._create_chain(chain_name)
            self._reconcile_chain(chain_name, desired_chains[chain_name])

        # Ensure FORWARD refs
        for chain_name, subnet in chain_to_subnet.items():
            if not self._forward_ref_exists(subnet, chain_name):
                self._run_iptables(
                    "-t",
                    FIREWALL_TABLE,
                    "-I",
                    "FORWARD",
                    "1",
                    "-s",
                    subnet,
                    "-j",
                    chain_name,
                )

        # Remove stale chains
        for chain_name in managed_chains - desired_names:
            try:
                self._remove_chain(chain_name)
            except RuntimeError:
                LOG.warning(
                    "Chain is still used, will try in next iteration...", exc_info=True
                )

    def _list_managed_chains(self, chain_prefixes):
        """List existing iptables chains matching our prefix(es).

        Uses iptables-save -t filter to get only the filter table,
        then extracts chain names from declaration lines.
        """
        result = subprocess.run(
            [IPTABLES_SAVE_BIN, "-t", FIREWALL_TABLE],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to list iptables chains: "
                f"rc={result.returncode} stderr={result.stderr.strip()}"
            )
        chains = set()
        for line in result.stdout.splitlines():
            if line.startswith(":"):
                chain_name = line.split()[0][1:]
                if any(chain_name.startswith(p + "_") for p in chain_prefixes):
                    chains.add(chain_name)
        return chains

    def _get_chain_rules(self, chain_name):
        """Get current rules for a chain using iptables -S.

        Returns dict with "accept" (set) and "drop" (str|None).
        """
        result = subprocess.run(
            [IPTABLES_BIN_PATH, "-t", FIREWALL_TABLE, "-S", chain_name],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to get rules for chain {chain_name}: "
                f"rc={result.returncode} stderr={result.stderr.strip()}"
            )
        accept = set()
        drop = None
        for line in result.stdout.splitlines():
            if line.startswith(f"-A {chain_name} "):
                if line.endswith(" -j DROP"):
                    drop = line
                else:
                    accept.add(line)
        return {"accept": accept, "drop": drop}

    def _forward_ref_exists(self, subnet, chain_name):
        """Check if a FORWARD rule exists using iptables -C."""
        result = subprocess.run(
            [
                IPTABLES_BIN_PATH,
                "-t",
                FIREWALL_TABLE,
                "-C",
                "FORWARD",
                "-s",
                subnet,
                "-j",
                chain_name,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0

    def _create_chain(self, chain_name):
        """Create a new iptables chain."""
        self._run_iptables(
            "-t",
            FIREWALL_TABLE,
            "-N",
            chain_name,
        )

    def _remove_chain(self, chain_name):
        """Remove a chain: flush rules, delete FORWARD refs, delete chain."""
        self._run_iptables("-t", FIREWALL_TABLE, "-F", chain_name)
        self._remove_forward_refs(chain_name)
        self._run_iptables("-t", FIREWALL_TABLE, "-X", chain_name)

    def _remove_forward_refs(self, chain_name):
        """Delete all FORWARD rules that jump to chain_name.

        Reads the full rule spec via -S so each deletion includes all
        match criteria (e.g. -s subnet) that iptables requires for an
        exact match.
        """
        result = subprocess.run(
            [IPTABLES_BIN_PATH, "-t", FIREWALL_TABLE, "-S", "FORWARD"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return
        for line in result.stdout.splitlines():
            if line.startswith("-A FORWARD ") and line.endswith(f"-j {chain_name}"):
                parts = line.split()
                self._run_iptables("-t", FIREWALL_TABLE, "-D", "FORWARD", *parts[2:])

    def _reconcile_chain(self, chain_name, desired):
        """Reconcile a single chain against desired rules.

        Uses incremental updates instead of flush+rebuild to avoid
        windows without protection. DROP is ensured first (fail-closed),
        then new ACCEPT rules are added before stale ones are removed.
        """
        current = self._get_chain_rules(chain_name)
        if (
            current["accept"] == desired["accept"]
            and current["drop"] == desired["drop"]
        ):
            return

        # Ensure DROP exists first (fail-closed safety net)
        if desired["drop"] and not current["drop"]:
            parts = desired["drop"].split()
            self._run_iptables("-t", FIREWALL_TABLE, "-A", chain_name, *parts[2:])

        # Add new ACCEPT rules before DROP (insert at position 1)
        new_accept = desired["accept"] - current["accept"]
        for rule in new_accept:
            parts = rule.split()
            self._run_iptables("-t", FIREWALL_TABLE, "-I", chain_name, "1", *parts[2:])

        # Remove stale ACCEPT rules
        stale_accept = current["accept"] - desired["accept"]
        for rule in stale_accept:
            parts = rule.split()
            self._run_iptables("-t", FIREWALL_TABLE, "-D", chain_name, *parts[2:])

        # Update DROP if it changed (delete old, append new at end)
        if desired["drop"] and current["drop"] and current["drop"] != desired["drop"]:
            old_parts = current["drop"].split()
            self._run_iptables("-t", FIREWALL_TABLE, "-D", chain_name, *old_parts[2:])
            new_parts = desired["drop"].split()
            self._run_iptables("-t", FIREWALL_TABLE, "-A", chain_name, *new_parts[2:])

    def _run_iptables(self, *args):
        """Run an iptables command, raising on any failure."""
        result = subprocess.run(
            [IPTABLES_BIN_PATH] + list(args),
            capture_output=True,
            text=True,
            timeout=10,
        )
        LOG.debug("_run_iptables: %r", args)
        if result.returncode != 0:
            raise RuntimeError(
                f"Iptables failed: {' '.join(args)}\n"
                f"rc={result.returncode} stderr={result.stderr}\n"
                f"stdout={result.stdout}"
            )

    def process_instance(
        self, name, conf, accounts, services=(), resolved_domains=None
    ):
        instance_subnet = netaddr.IPNetwork(conf.openvpn_subnet_cidr)
        dir = conf.openvpn_config_dir
        ccd_dir = os.path.join(dir, f"ccd_{name}" if name else "ccd")
        if not os.path.exists(ccd_dir):
            os.makedirs(ccd_dir)
        resolved_domains = resolved_domains or {}
        private_networks = _parse_private_networks(
            getattr(conf, "private_networks", "")
        )
        for account in accounts:
            LOG.info("(%s)Processing account: %s", name, account.account_name)
            ccd_file_path = os.path.join(ccd_dir, account.account_name)
            with open(ccd_file_path, "w") as f:
                if account.status == "DISABLED":
                    f.write("disable\n")
                    continue

                if not account.address_offset:
                    LOG.warning(
                        "Ignore active account without address_offset: %r",
                        account.account_name,
                    )
                    f.write("disable\n")
                    continue

                try:
                    client_ip, _ = account.network.ip_for_offset(account.address_offset)
                except ValueError as e:
                    LOG.warning(
                        "Cannot resolve IP for account %r: %s", account.account_name, e
                    )
                    f.write("disable\n")
                    continue

                f.write(f"ifconfig-push {client_ip} {instance_subnet.netmask}\n")
                for line in _build_ccd_push_lines(
                    account, services, resolved_domains, private_networks
                ):
                    f.write(f"{line}\n")
