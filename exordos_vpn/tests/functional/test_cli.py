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

import json

from click.testing import CliRunner
import netaddr
from restalchemy.common import contexts
from restalchemy.dm import filters as dm_filters

from exordos_vpn.cmd import cli
from exordos_vpn.dm import models
from exordos_vpn.tests.functional import base


class CliTestCase(base.DbTestCase):
    """Base for CLI functional tests.

    `_ensure_config` is monkeypatched to skip oslo_config/config-file
    bootstrap (which needs certificate/OTP settings irrelevant to these
    commands) and just hand out a Context bound to the already-configured
    test engine, so commands run against a real DB exactly as they would
    in production, minus the parts of `_ensure_config` unrelated to what's
    under test here.
    """

    def setup_method(self):
        super().setup_method()
        self.runner = CliRunner()

    def _invoke(self, monkeypatch, args):
        def fake_ensure_config(ctx):
            ctx.obj["session_ctx"] = contexts.Context()
            ctx.obj["_config_initialized"] = True

        monkeypatch.setattr(cli, "_ensure_config", fake_ensure_config)
        return self.runner.invoke(cli.cli, args, catch_exceptions=True)


class TestServiceCli(CliTestCase):
    """Functional tests for the `service-*` CLI commands."""

    def _get_service(self, name):
        with contexts.Context().session_manager() as s:
            return models.Service.objects.get_one(
                session=s, filters={"name": dm_filters.EQ(name)}
            )

    def test_service_create_with_domains_and_nexthop(self, monkeypatch):
        result = self._invoke(
            monkeypatch,
            [
                "service-create",
                "ext-svc",
                "--domains",
                "github.com,api.github.com",
                "--nexthop",
                "127.0.0.2",
                "--tags",
                "git",
            ],
        )

        assert result.exit_code == 0, result.output
        service = self._get_service("ext-svc")
        assert service.domains == ["github.com", "api.github.com"]
        assert str(service.nexthop) == "127.0.0.2"
        assert service.tags == ["git"]

    def test_service_create_without_subnets_or_domains_fails(self, monkeypatch):
        result = self._invoke(monkeypatch, ["service-create", "empty-svc"])

        assert result.exit_code != 0
        with contexts.Context().session_manager() as s:
            count = models.Service.objects.count(
                session=s, filters={"name": dm_filters.EQ("empty-svc")}
            )
        assert count == 0

    def test_service_list_shows_domains_and_nexthop(self, monkeypatch):
        service = models.Service(
            name="listed-svc",
            domains=["example.com"],
            nexthop=netaddr.IPAddress("127.0.0.3"),
            tags=["ext"],
        )
        service.insert()

        result = self._invoke(monkeypatch, ["--format", "json", "service-list"])

        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        row = next(r for r in rows if r["name"] == "listed-svc")
        assert row["domains"] == "example.com"
        assert row["nexthop"] == "127.0.0.3"

    def test_service_reset_clears_nexthop_with_empty_string(self, monkeypatch):
        service = models.Service(
            name="reset-svc",
            subnets=[netaddr.IPNetwork("172.16.0.0/24")],
            nexthop=netaddr.IPAddress("127.0.0.4"),
        )
        service.insert()

        result = self._invoke(
            monkeypatch,
            ["service-reset", str(service.uuid), "--nexthop", ""],
        )

        assert result.exit_code == 0, result.output
        refreshed = self._get_service("reset-svc")
        assert refreshed.nexthop is None

    def test_service_cannot_lose_last_subnet_and_domain(self, monkeypatch):
        """Service.validate() runs on UPDATE too, so remove-*/reset can't
        strip the last subnet/domain and leave an empty service behind."""
        service = models.Service(
            name="last-svc", subnets=[netaddr.IPNetwork("172.16.0.0/24")]
        )
        service.insert()

        result = self._invoke(
            monkeypatch,
            ["service-remove-subnet", str(service.uuid), "172.16.0.0/24"],
        )

        assert result.exit_code != 0
        assert self._get_service("last-svc").subnets == [
            netaddr.IPNetwork("172.16.0.0/24")
        ]

    def test_service_add_and_remove_domain(self, monkeypatch):
        service = models.Service(name="domain-svc", domains=["github.com"])
        service.insert()

        add_result = self._invoke(
            monkeypatch,
            ["service-add-domain", str(service.uuid), "gitlab.com"],
        )
        assert add_result.exit_code == 0, add_result.output
        assert set(self._get_service("domain-svc").domains) == {
            "github.com",
            "gitlab.com",
        }

        remove_result = self._invoke(
            monkeypatch,
            ["service-remove-domain", str(service.uuid), "github.com"],
        )
        assert remove_result.exit_code == 0, remove_result.output
        assert self._get_service("domain-svc").domains == ["gitlab.com"]


class TestAccountOtpRequiredCli(CliTestCase):
    """Functional tests for the `account-otp-required` toggle command."""

    def _make_account(self, name="alice"):
        network = models.Network(
            name="testnet", subnets=[netaddr.IPNetwork("10.8.0.0/24")]
        )
        network.insert()
        account = models.Account(
            account_name=name,
            user_id=f"user-{name}",
            pin="123456",
            network=network,
            address_offset=2,
        )
        account.insert()
        return account

    def _get_account(self, name):
        with contexts.Context().session_manager() as s:
            return models.Account.objects.get_one(
                session=s, filters={"account_name": dm_filters.EQ(name)}
            )

    def test_otp_required_off_and_back_on(self, monkeypatch):
        account = self._make_account()
        assert account.otp_required is True

        off_result = self._invoke(monkeypatch, ["account-otp-required", "alice", "off"])
        assert off_result.exit_code == 0, off_result.output
        assert "PIN-only" in off_result.output
        assert self._get_account("alice").otp_required is False

        on_result = self._invoke(monkeypatch, ["account-otp-required", "alice", "on"])
        assert on_result.exit_code == 0, on_result.output
        # No active OTP device linked — the operator must be warned the
        # account is now locked out until one is issued.
        assert "no active OTP" in on_result.output
        assert self._get_account("alice").otp_required is True

    def _cached_logins(self, account):
        with contexts.Context().session_manager() as s:
            return models.AccountAuthCache.objects.count(
                session=s, filters={"account": dm_filters.EQ(account)}
            )

    def test_toggle_clears_auth_cache(self, monkeypatch):
        """A cached login must not outlive the toggle: e.g. a PIN-only
        password cached while OTP was off would keep authenticating after
        OTP is re-enabled."""
        account = self._make_account()
        account.update_auth_cache("123456000000")
        assert self._cached_logins(account) == 1

        result = self._invoke(monkeypatch, ["account-otp-required", "alice", "off"])
        assert result.exit_code == 0, result.output
        assert self._cached_logins(account) == 0

        account.update_auth_cache("123456")
        result = self._invoke(monkeypatch, ["account-otp-required", "alice", "on"])
        assert result.exit_code == 0, result.output
        assert self._cached_logins(account) == 0

    def test_noop_toggle_keeps_auth_cache(self, monkeypatch):
        """Re-running the command with the current value must not kick a
        (still consistent) cached login."""
        account = self._make_account()
        account.update_auth_cache("123456000000")

        result = self._invoke(monkeypatch, ["account-otp-required", "alice", "on"])
        assert result.exit_code == 0, result.output
        assert self._cached_logins(account) == 1


class TestDepartmentCli(CliTestCase):
    """Functional tests for the `department-*` / `account-department-*`
    CLI commands."""

    def _make_account(self, name="alice"):
        network = models.Network(
            name="testnet", subnets=[netaddr.IPNetwork("10.8.0.0/24")]
        )
        network.insert()
        account = models.Account(
            account_name=name,
            user_id=f"user-{name}",
            pin="123456",
            network=network,
            address_offset=2,
        )
        account.insert()
        return account

    def _get_department(self, name):
        with contexts.Context().session_manager() as s:
            return models.Department.objects.get_one(
                session=s, filters={"name": dm_filters.EQ(name)}
            )

    def _membership_count(self, account):
        with contexts.Context().session_manager() as s:
            return models.AccountDepartment.objects.count(
                session=s, filters={"account": dm_filters.EQ(account)}
            )

    def test_department_create_with_parent_and_tags(self, monkeypatch):
        root = self._invoke(
            monkeypatch, ["department-create", "org", "--tags", "vpn-basic"]
        )
        assert root.exit_code == 0, root.output

        child = self._invoke(
            monkeypatch,
            ["department-create", "engineering", "--parent", "org", "--tags", "git"],
        )
        assert child.exit_code == 0, child.output

        engineering = self._get_department("engineering")
        assert engineering.parent == self._get_department("org").uuid
        assert engineering.network_access_tags == ["git"]

    def test_department_set_parent_refuses_cycle(self, monkeypatch):
        self._invoke(monkeypatch, ["department-create", "org"])
        self._invoke(monkeypatch, ["department-create", "child", "--parent", "org"])

        result = self._invoke(monkeypatch, ["department-set-parent", "org", "child"])

        assert result.exit_code != 0
        assert "cycle" in result.output
        assert self._get_department("org").parent is None

    def test_department_set_parent_empty_makes_root(self, monkeypatch):
        self._invoke(monkeypatch, ["department-create", "org"])
        self._invoke(monkeypatch, ["department-create", "child", "--parent", "org"])

        result = self._invoke(monkeypatch, ["department-set-parent", "child", ""])

        assert result.exit_code == 0, result.output
        assert self._get_department("child").parent is None

    def _make_org_tree(self, monkeypatch):
        self._invoke(monkeypatch, ["department-create", "org", "--tags", "web"])
        self._invoke(
            monkeypatch,
            ["department-create", "backend", "--parent", "org", "--tags", "git"],
        )
        self._invoke(monkeypatch, ["department-create", "sales"])

    def test_department_list_tree(self, monkeypatch):
        self._make_org_tree(monkeypatch)

        result = self._invoke(monkeypatch, ["department-list", "--tree"])

        assert result.exit_code == 0, result.output
        lines = result.output.splitlines()
        assert "org (web)" in lines
        assert "└── backend (git) (+web)" in lines
        assert "sales" in lines

    def test_department_list_tree_json(self, monkeypatch):
        self._make_org_tree(monkeypatch)

        result = self._invoke(
            monkeypatch, ["--format", "json", "department-list", "--tree"]
        )

        assert result.exit_code == 0, result.output
        roots = json.loads(result.output)
        assert [r["name"] for r in roots] == ["org", "sales"]
        org = roots[0]
        assert [c["name"] for c in org["children"]] == ["backend"]
        backend = org["children"][0]
        assert backend["tags"] == ["git"]
        assert backend["effective_tags"] == ["git", "web"]
        assert backend["children"] == []

    def test_department_list_tree_renders_cycle_members(self, monkeypatch):
        # a parent cycle can't be created via CLI/API, only by manual DB
        # edits; the tree must still show its members instead of hanging
        # or dropping them
        a = models.Department(name="a")
        a.insert()
        b = models.Department(name="b", parent=a.uuid)
        b.insert()
        with contexts.Context().session_manager() as s:
            a = models.Department.objects.get_one(
                session=s, filters={"name": dm_filters.EQ("a")}
            )
            a.parent = b.uuid
            a.save(session=s)

        result = self._invoke(monkeypatch, ["department-list", "--tree"])

        assert result.exit_code == 0, result.output
        assert "a" in result.output.split()
        assert "└── b" in result.output

    def test_account_department_add_remove(self, monkeypatch):
        account = self._make_account()
        self._invoke(monkeypatch, ["department-create", "engineering"])

        add = self._invoke(
            monkeypatch, ["account-department-add", "alice", "engineering"]
        )
        assert add.exit_code == 0, add.output
        assert self._membership_count(account) == 1

        # Idempotent: adding again doesn't duplicate the link.
        self._invoke(monkeypatch, ["account-department-add", "alice", "engineering"])
        assert self._membership_count(account) == 1

        remove = self._invoke(
            monkeypatch, ["account-department-remove", "alice", "engineering"]
        )
        assert remove.exit_code == 0, remove.output
        assert self._membership_count(account) == 0

    def test_account_show_displays_departments_and_effective_tags(self, monkeypatch):
        account = self._make_account()
        with contexts.Context().session_manager() as s:
            account = models.Account.objects.get_one(
                session=s, filters={"account_name": dm_filters.EQ("alice")}
            )
            account.network_access_tags = ["own"]
            account.save(session=s)
        self._invoke(monkeypatch, ["department-create", "org", "--tags", "web"])
        self._invoke(
            monkeypatch,
            ["department-create", "backend", "--parent", "org", "--tags", "git"],
        )
        self._invoke(monkeypatch, ["account-department-add", "alice", "backend"])

        result = self._invoke(monkeypatch, ["account-show", "alice"])

        assert result.exit_code == 0, result.output
        assert "Departments: backend" in result.output
        assert "Effective tags (own + departments): git, own, web" in result.output
        assert "OTP: required" in result.output
        assert "Client IP:" in result.output

    def test_account_network_show_is_deprecated_alias_of_account_show(
        self, monkeypatch
    ):
        self._make_account()

        result = self._invoke(monkeypatch, ["account-network-show", "alice"])

        assert result.exit_code == 0, result.output
        assert "deprecated" in result.output
        # Full account-show output, not the old short network-rules one.
        assert "Effective tags (own + departments):" in result.output
        assert "OTP devices:" in result.output

    def test_account_list_full_shows_departments(self, monkeypatch):
        self._make_account()
        self._invoke(monkeypatch, ["department-create", "engineering", "--tags", "git"])
        self._invoke(monkeypatch, ["account-department-add", "alice", "engineering"])

        result = self._invoke(
            monkeypatch, ["--format", "json", "account-list", "--full"]
        )

        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        row = next(r for r in rows if r["account_name"] == "alice")
        assert row["departments"] == "engineering"
        assert row["effective_tags"] == "git"

    def test_department_delete_refused_with_members_then_ok(self, monkeypatch):
        self._make_account()
        self._invoke(monkeypatch, ["department-create", "engineering"])
        self._invoke(monkeypatch, ["account-department-add", "alice", "engineering"])

        refused = self._invoke(monkeypatch, ["department-delete", "engineering"])
        assert refused.exit_code != 0
        assert "member accounts" in refused.output

        self._invoke(monkeypatch, ["account-department-remove", "alice", "engineering"])
        deleted = self._invoke(monkeypatch, ["department-delete", "engineering"])
        assert deleted.exit_code == 0, deleted.output
        with contexts.Context().session_manager() as s:
            assert (
                models.Department.objects.get_one_or_none(
                    session=s, filters={"name": dm_filters.EQ("engineering")}
                )
                is None
            )
