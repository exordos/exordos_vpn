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


class TestServiceCli(base.DbTestCase):
    """Functional tests for the `service-*` CLI commands.

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
