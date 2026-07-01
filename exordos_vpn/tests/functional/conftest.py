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
import select
import subprocess

from oslo_config import cfg
import pytest

from exordos_vpn.common import config as vpn_config
from exordos_vpn.common import constants as c
from exordos_vpn.services import server_agent

# Real, isolated net namespace so firewall functional tests exercise the
# actual iptables binary (not a fake). We tried the unprivileged
# `unshare --user --map-root-user` trick to avoid sudo, but CI runners
# (Ubuntu 24.04) block unprivileged user namespace creation (AppArmor /
# kernel.unprivileged_userns_clone), failing with "write failed
# /proc/self/uid_map: Operation not permitted". So we use real root via
# passwordless `sudo` instead (guaranteed on GitHub-hosted runners, and
# what this project's CI already relies on for `apt install`). The
# namespace is empty (no host interfaces, no host firewall state), so
# it's safe to mutate.
#
# `sudo CMD` does not exec in place: it forks a monitor process, so the
# PID returned by Popen() is *not* inside the new namespace. We print the
# real inner PID (`$$` after unshare has already run) and read it back,
# instead of assuming it matches the Popen PID.
_SENTINEL_CMD = [
    "sudo",
    "-n",
    "unshare",
    "--net",
    "--",
    "sh",
    "-c",
    "echo READY $$; exec sleep 3600",
]


@pytest.fixture(scope="session", autouse=True)
def global_salt():
    """Register and set the global salt required to hash Account PINs."""
    cfg.CONF.register_opts(vpn_config.service_config_opts, c.COMMON_DOMAIN)
    cfg.CONF.set_override(
        "global_salt",
        base64.b64encode(b"test-salt-not-for-prod-use").decode(),
        group=c.COMMON_DOMAIN,
    )


def _nsenter_prefix(pid):
    return ["sudo", "-n", "nsenter", "-t", str(pid), "-n"]


def _start_netns_sentinel(timeout=5.0):
    """Start the sentinel and return (process_handle, real_inner_pid).

    process_handle is used for lifecycle (terminate/wait); real_inner_pid
    is the pid to target with nsenter (see module docstring above).
    """
    proc = subprocess.Popen(
        _SENTINEL_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    if not ready:
        proc.kill()
        proc.wait()
        raise RuntimeError("timed out waiting for netns sentinel to start")

    line = proc.stdout.readline()
    if not line.startswith("READY "):
        stderr = proc.stderr.read() if proc.stderr else ""
        proc.wait()
        raise RuntimeError(
            f"sentinel process failed to start (exit {proc.returncode}): "
            f"{stderr.strip()}"
        )
    return proc, int(line.split()[1])


class IptablesNetns:
    """Handle to an isolated netns where iptables calls are actually run."""

    def __init__(self, pid, calls):
        self.pid = pid
        self.calls = calls

    def run(self, *iptables_args):
        """Run an arbitrary iptables/iptables-save command in the netns directly."""
        result = subprocess.run(
            _nsenter_prefix(self.pid) + list(iptables_args),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Iptables failed: {' '.join(iptables_args)}\n"
                f"rc={result.returncode} stderr={result.stderr}"
            )
        return result.stdout

    def get_chain_rules(self, chain_name):
        out = self.run(server_agent.IPTABLES_BIN_PATH, "-t", "filter", "-S", chain_name)
        return out.splitlines()

    def mutating_calls(self):
        """Calls issued since the last reset that change firewall state."""
        mutating_flags = {"-N", "-X", "-F", "-A", "-I", "-D"}
        return [c for c in self.calls if mutating_flags & set(c)]

    def reset_calls(self):
        self.calls.clear()


def _cleanup_sentinel(proc):
    # SIGKILL to the wrapping `sudo` process is not forwarded to its child,
    # which would leak a root-owned `sleep 3600` behind; SIGTERM is.
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    if proc.stdout:
        proc.stdout.close()
    if proc.stderr:
        proc.stderr.close()


@pytest.fixture
def iptables_netns(monkeypatch):
    try:
        proc, inner_pid = _start_netns_sentinel()
    except (FileNotFoundError, RuntimeError) as e:
        pytest.fail(
            "Real-iptables functional tests need a root-owned network "
            f"namespace (via passwordless sudo); unavailable here: {e}",
            pytrace=False,
        )

    real_run = subprocess.run
    try:
        real_run(
            _nsenter_prefix(inner_pid) + ["ip", "link", "set", "lo", "up"],
            check=True,
            capture_output=True,
            text=True,
        )
    except Exception as e:
        _cleanup_sentinel(proc)
        pytest.fail(f"Failed to prepare iptables netns: {e}", pytrace=False)

    calls = []
    iptables_bins = {server_agent.IPTABLES_BIN_PATH, server_agent.IPTABLES_SAVE_BIN}

    def netns_run(cmd, *args, **kwargs):
        if cmd and cmd[0] in iptables_bins:
            calls.append(list(cmd))
            cmd = _nsenter_prefix(inner_pid) + list(cmd)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(server_agent.subprocess, "run", netns_run)

    try:
        yield IptablesNetns(inner_pid, calls)
    finally:
        _cleanup_sentinel(proc)
