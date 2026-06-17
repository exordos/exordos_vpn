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

import netaddr
from gcl_looper.services import basic
from restalchemy.common import contexts
from restalchemy.dm import filters as dm_filters
from restalchemy.dm import types

from exordos_vpn.dm import models


LOG = logging.getLogger(__name__)

IPTABLES_SAVE_BIN = "iptables-save"
IPTABLES_BIN_PATH = "/usr/sbin/iptables"
FIREWALL_TABLE = "filter"


def _host_cidr(ip):
    """Return a host IP in /32 CIDR notation as iptables normalizes it."""
    return f"{ip}/32"


def _build_kind_rules(chain_name, client_ip, subnet, kind):
    """Build iptables ACCEPT rule for a single kind.

    For 'any' kind: unrestricted access to the subnet.
    For 'tcp'/'udp' kind: protocol-specific access with port range.

    Returns:
        set of rule strings (may contain multiple rules for port ranges)
    """
    src = _host_cidr(client_ip)
    if kind.KIND == "any":
        return {f"-A {chain_name} -s {src} -d {subnet} -j ACCEPT"}

    protocol = kind.KIND
    min_port = kind.min_port
    max_port = kind.max_port
    rules = set()

    if min_port == 1 and max_port == 65535:
        rules.add(f"-A {chain_name} -s {src} -d {subnet} -p {protocol} -j ACCEPT")
    elif min_port == max_port:
        rules.add(
            f"-A {chain_name} -s {src} -d {subnet} "
            f"-p {protocol} --dport {min_port} -j ACCEPT"
        )
    else:
        rules.add(
            f"-A {chain_name} -s {src} -d {subnet} "
            f"-p {protocol} --dport {min_port}:{max_port} -j ACCEPT"
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
            LOG.warning("Cannot resolve IP for account %r, skipping firewall rules", account.account_name)
            continue
        src = _host_cidr(client_ip)
        if account.network_access_type == "ALL":
            accept_rules.add(f"-A {chain_name} -s {src} -j ACCEPT")
        else:
            account_tags = set(account.network_access_tags or [])
            for service in services:
                service_tags = set(service.tags or [])
                if account_tags & service_tags:
                    service_kinds = service.kinds
                    if not service_kinds:
                        for subnet in service.subnets:
                            accept_rules.add(
                                f"-A {chain_name} -s {src} -d {subnet} -j ACCEPT"
                            )
                    else:
                        for subnet in service.subnets:
                            for kind in service_kinds:
                                accept_rules.update(
                                    _build_kind_rules(
                                        chain_name, client_ip, subnet, kind
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


class AgentService(basic.BasicService):
    def __init__(self, prefixes=None, **kwargs):
        self.prefixes = prefixes
        self._ctx = contexts.Context()
        self.last_processed_at = datetime.datetime.strptime(
            "2000-01-01T00:00:00.000000Z", types.OPENAPI_DATETIME_FMT
        )
        # lag to avoid race conditions
        self.lag = datetime.timedelta(seconds=30)
        super().__init__(**kwargs)

    def _iteration(self):
        iter_started = datetime.datetime.now(datetime.timezone.utc)

        # Reconcile firewall with incremental data first
        if self._has_firewall_data_changed() and self.prefixes:
            self._reconcile_firewall()

        # CCD: incremental fetch of accounts updated since last cycle
        with self._ctx.session_manager() as s:
            filters = {
                "updated_at": dm_filters.GE(self.last_processed_at),
            }
            accounts = models.Account.objects.get_all(session=s, filters=filters)

        for name, conf in self.prefixes.items():
            self.process_instance(name, conf, accounts)

        # Update cursor after processing both CCD and firewall
        self.last_processed_at = iter_started - self.lag

    def _has_firewall_data_changed(self):
        """Check if any accounts or services changed since last reconciliation.

        Returns True if a full snapshot is needed for firewall reconciliation.
        """
        with self._ctx.session_manager() as s:
            filters = {
                "updated_at": dm_filters.GE(self.last_processed_at),
            }
            if models.Account.objects.count(session=s, filters=filters):
                return True
            if models.Service.objects.count(session=s, filters=filters):
                return True
        return False

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
            vpn_subnet = netaddr.IPNetwork(vpn_subnet_raw)
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

        # Remove stale chains first
        for chain_name in managed_chains - desired_names:
            try:
                self._remove_chain(chain_name)
            except RuntimeError:
                LOG.warning('Chain is still used, will try in next iteration...', exc_info=True)

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
        # Flush all rules in the chain
        self._run_iptables("-t", FIREWALL_TABLE, "-F", chain_name)
        # Remove all FORWARD references to this chain
        while True:
            result = subprocess.run(
                [
                    IPTABLES_BIN_PATH,
                    "-t",
                    FIREWALL_TABLE,
                    "-D",
                    "FORWARD",
                    "-j",
                    chain_name,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                break
        # Delete the chain
        self._run_iptables(
            "-t",
            FIREWALL_TABLE,
            "-X",
            chain_name,
        )

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
        if result.returncode != 0:
            raise RuntimeError(
                f"Iptables failed: {' '.join(args)}\n"
                f"rc={result.returncode} stderr={result.stderr}\n"
                f"stdout={result.stdout}"
            )

    def process_instance(self, name, conf, accounts):
        instance_subnet = netaddr.IPNetwork(conf.openvpn_subnet_cidr)
        dir = conf.openvpn_config_dir
        ccd_dir = os.path.join(dir, f"ccd_{name}" if name else "ccd")
        if not os.path.exists(ccd_dir):
            os.makedirs(ccd_dir)
        for account in accounts:
            LOG.info(f"({name})Processing account: {account.account_name}")
            ccd_file_path = os.path.join(ccd_dir, account.account_name)
            with open(ccd_file_path, "w") as f:
                if account.status == "DISABLED":
                    f.write("disable\n")
                    continue

                if not account.address_offset:
                    LOG.warning("Ignore active account without address_offset: %r", account.account_name)
                    f.write("disable\n")
                    continue

                try:
                    client_ip, _ = account.network.ip_for_offset(account.address_offset)
                except ValueError as e:
                    LOG.warning("Cannot resolve IP for account %r: %s", account.account_name, e)
                    f.write("disable\n")
                    continue

                f.write(f"ifconfig-push {client_ip} {instance_subnet.netmask}\n")
