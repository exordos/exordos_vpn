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
import json
import uuid

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

    def test_service_reset_accepts_name(self, monkeypatch):
        service = models.Service(
            name="named-svc", subnets=[netaddr.IPNetwork("172.16.0.0/24")]
        )
        service.insert()

        result = self._invoke(
            monkeypatch,
            ["service-reset", "named-svc", "--tags", "web"],
        )

        assert result.exit_code == 0, result.output
        assert self._get_service("named-svc").tags == ["web"]

    def test_service_not_found_reports_error(self, monkeypatch):
        result = self._invoke(monkeypatch, ["service-reset", "no-such-svc"])

        assert result.exit_code != 0
        assert "Service not found: no-such-svc" in result.output

    def test_service_set_nexthop_and_clear(self, monkeypatch):
        service = models.Service(
            name="hop-svc", subnets=[netaddr.IPNetwork("172.16.0.0/24")]
        )
        service.insert()

        result = self._invoke(
            monkeypatch, ["service-set-nexthop", "hop-svc", "127.0.0.5"]
        )
        assert result.exit_code == 0, result.output
        assert str(self._get_service("hop-svc").nexthop) == "127.0.0.5"

        result = self._invoke(monkeypatch, ["service-set-nexthop", "hop-svc", ""])
        assert result.exit_code == 0, result.output
        assert self._get_service("hop-svc").nexthop is None

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


class TestAddressAllocationCli(CliTestCase):
    """Functional tests for address-allocation history: the model hooks
    that open/close ownership spans and the `address-*` CLI commands."""

    def _make_network(self, cidr="10.8.0.0/24"):
        network = models.Network(name="testnet", subnets=[netaddr.IPNetwork(cidr)])
        network.insert()
        return network

    def _make_account(self, network, name, offset):
        account = models.Account(
            account_name=name,
            user_id=f"user-{name}",
            pin="123456",
            network=network,
            address_offset=offset,
        )
        account.insert()
        return account

    def _allocations(self, **filters):
        f = {k: dm_filters.EQ(v) for k, v in filters.items()}
        with contexts.Context().session_manager() as s:
            allocs = models.AddressAllocation.objects.get_all(session=s, filters=f)
        return sorted(allocs, key=lambda a: a.allocated_at)

    def test_account_insert_opens_span(self):
        network = self._make_network()
        account = self._make_account(network, "alice", 2)

        allocs = self._allocations(account_uuid=str(account.uuid))
        assert len(allocs) == 1
        span = allocs[0]
        assert span.ip == "10.8.0.2"
        assert span.account_name == "alice"
        assert span.user_id == "user-alice"
        assert span.network_name == "testnet"
        assert span.address_offset == 2
        assert span.released_at is None
        assert span.release_reason is None

    def test_scheduler_closes_span_and_reuse_records_new_owner(self):
        from exordos_vpn.services import scheduler

        network = self._make_network()
        first = self._make_account(network, "alice", 2)

        # Disable and backdate so the scheduler treats the offset as stale.
        with contexts.Context().session_manager() as s:
            s.execute(
                "UPDATE accounts SET status='DISABLED', "
                "updated_at=NOW() - INTERVAL '10 days' WHERE uuid=%s",
                (str(first.uuid),),
            )

        scheduler.SchedulerService(offset_days=1)._iteration()

        # The offset is freed and its span closed as a scheduler cleanup.
        with contexts.Context().session_manager() as s:
            refreshed = models.Account.objects.get_one(
                session=s, filters={"uuid": dm_filters.EQ(str(first.uuid))}
            )
        assert refreshed.address_offset is None

        first_span = self._allocations(account_uuid=str(first.uuid))[0]
        assert first_span.released_at is not None
        assert first_span.release_reason == "scheduler_cleanup"

        # A new account reuses offset 2 (same IP) -> fresh open span.
        second = self._make_account(network, "bob", 2)
        ip_spans = self._allocations(ip="10.8.0.2")
        assert len(ip_spans) == 2
        assert ip_spans[0].account_name == "alice"
        assert ip_spans[1].account_name == "bob"
        assert ip_spans[1].released_at is None
        assert {s.account_uuid for s in ip_spans} == {first.uuid, second.uuid}

    def test_address_history_json_export(self, monkeypatch):
        network = self._make_network()
        self._make_account(network, "alice", 2)

        result = self._invoke(
            monkeypatch,
            ["--format", "json", "address-history", "--ip", "10.8.0.2"],
        )
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        assert len(rows) == 1
        assert rows[0]["ip"] == "10.8.0.2"
        assert rows[0]["account_name"] == "alice"
        assert rows[0]["status"] == "active"
        assert rows[0]["released_at"] == "-"

    def test_address_list_shows_current_owner_and_count(self, monkeypatch):
        network = self._make_network()
        first = self._make_account(network, "alice", 2)
        # Release alice's span, then hand offset 2 to bob.
        models.AddressAllocation.close_open_for_account(
            str(first.uuid), reason="manual"
        )
        with contexts.Context().session_manager() as s:
            s.execute(
                "UPDATE accounts SET address_offset=NULL WHERE uuid=%s",
                (str(first.uuid),),
            )
        self._make_account(network, "bob", 2)

        result = self._invoke(monkeypatch, ["--format", "json", "address-list"])
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        row = next(r for r in rows if r["ip"] == "10.8.0.2")
        assert row["current_owner"] == "bob"
        assert row["owners"] == 2

    def test_address_list_history_flag_dumps_all_owners(self, monkeypatch):
        network = self._make_network()
        first = self._make_account(network, "alice", 2)
        models.AddressAllocation.close_open_for_account(
            str(first.uuid), reason="manual"
        )
        with contexts.Context().session_manager() as s:
            s.execute(
                "UPDATE accounts SET address_offset=NULL WHERE uuid=%s",
                (str(first.uuid),),
            )
        self._make_account(network, "bob", 2)

        result = self._invoke(
            monkeypatch, ["--format", "json", "address-list", "--history"]
        )
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        # Both ownership spans of 10.8.0.2 are expanded, oldest first.
        spans = [r for r in rows if r["ip"] == "10.8.0.2"]
        assert [r["account_name"] for r in spans] == ["alice", "bob"]
        assert spans[0]["status"] == "released"
        assert spans[0]["reason"] == "manual"
        assert spans[1]["status"] == "active"
        assert spans[1]["released_at"] == "-"

    def test_address_list_active_filter(self, monkeypatch):
        network = self._make_network()
        first = self._make_account(network, "alice", 2)
        models.AddressAllocation.close_open_for_account(
            str(first.uuid), reason="manual"
        )
        with contexts.Context().session_manager() as s:
            s.execute(
                "UPDATE accounts SET address_offset=NULL WHERE uuid=%s",
                (str(first.uuid),),
            )

        result = self._invoke(
            monkeypatch, ["--format", "json", "address-list", "--active"]
        )
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)
        # The only IP's span is released -> nothing active to show.
        assert rows == []

    def test_migration_backfills_existing_offset_holders(self):
        # Roll this migration back to the pre-0006 schema, plant an account
        # that already holds an offset, then re-apply 0006 and check the
        # back-fill opened a span dated to the account's creation time.
        migration = "0006-add-address-allocations-1e7b4d.py"
        engine = self.get_migration_engine()
        engine.rollback_migration(migration)

        net_uuid = str(uuid.uuid4())
        acc_uuid = str(uuid.uuid4())
        created = datetime.datetime(2026, 1, 2, 3, 4, 5)
        with contexts.Context().session_manager() as s:
            s.execute(
                "INSERT INTO networks "
                "(uuid, name, description, subnets, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, NOW(), NOW())",
                (net_uuid, "backfillnet", "", ["10.9.0.0/24"]),
            )
            s.execute(
                "INSERT INTO accounts "
                "(uuid, user_id, account_name, pin_hash, network, "
                "address_offset, created_at, updated_at) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())",
                (acc_uuid, "user-carol", "carol", "x", net_uuid, 3, created),
            )

        engine.apply_migration(migration)

        spans = self._allocations(account_uuid=acc_uuid)
        assert len(spans) == 1
        span = spans[0]
        assert span.ip == "10.9.0.3"
        assert span.netmask == "255.255.255.0"
        assert span.account_name == "carol"
        assert span.user_id == "user-carol"
        assert span.network_name == "backfillnet"
        assert span.released_at is None
        assert span.allocated_at.replace(tzinfo=None) == created
