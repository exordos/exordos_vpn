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

import types

import netaddr
import pyotp
import pytest
from restalchemy.common import contexts

from exordos_vpn.dm import models
from exordos_vpn.tests.functional import base
from exordos_vpn.user_api.api import controllers

PIN = "123456"


class TestAuthOtpRequired(base.DbTestCase):
    """Functional tests for AuthController PIN/OTP verification, focused
    on the per-account `otp_required` flag: with it off the whole password
    is the PIN and no OTP device is needed at all.
    """

    def _make_controller(self):
        request = types.SimpleNamespace(
            context=types.SimpleNamespace(get_user_ip=lambda: "127.0.0.1")
        )
        return controllers.AuthController(request=request)

    def _make_account(self, name="alice", otp_required=True):
        network = models.Network(
            name="testnet", subnets=[netaddr.IPNetwork("10.8.0.0/24")]
        )
        network.insert()
        account = models.Account(
            account_name=name,
            user_id=f"user-{name}",
            pin=PIN,
            network=network,
            address_offset=2,
            otp_required=otp_required,
        )
        account.insert()
        return account

    def _attach_otp_device(self, account):
        secret = pyotp.random_base32()
        device = models.OtpDevice(otp_secret=secret, user_id=account.user_id)
        device.insert()
        models.AccountOtpDevice(account=account, otp_device=device).insert()
        return secret

    def _auth(self, account_name, password):
        with contexts.Context().session_manager():
            return self._make_controller().create(
                account_name=account_name, password=password
            )

    def test_otp_disabled_pin_only_login_succeeds(self):
        """No OTP device exists at all — PIN alone must be enough."""
        self._make_account(otp_required=False)

        result, code, _, _ = self._auth("alice", PIN)

        assert code == 200
        assert result == {"status": "ok"}

    def test_otp_disabled_wrong_pin_fails(self):
        self._make_account(otp_required=False)

        with pytest.raises(controllers.AuthVerifyError):
            self._auth("alice", "654321")

    def test_otp_disabled_pin_with_otp_code_appended_fails(self):
        """The whole password is the PIN — a habitual PIN+OTP entry must
        not slip through."""
        self._make_account(otp_required=False)

        with pytest.raises(controllers.AuthVerifyError):
            self._auth("alice", PIN + "000000")

    def test_otp_required_pin_only_still_fails(self):
        """Default flow untouched: an OTP-required account cannot log in
        with just the PIN."""
        account = self._make_account(otp_required=True)
        self._attach_otp_device(account)

        with pytest.raises(controllers.AuthVerifyError):
            self._auth("alice", PIN)

    def test_otp_required_full_login_succeeds(self):
        account = self._make_account(otp_required=True)
        secret = self._attach_otp_device(account)

        result, code, _, _ = self._auth("alice", PIN + pyotp.TOTP(secret).now())

        assert code == 200
        assert result == {"status": "ok"}

    def test_otp_required_without_device_fails(self):
        """An OTP-required account with no active device stays locked out
        (pre-existing behavior; otp_required=False is the way to allow
        deviceless accounts)."""
        self._make_account(otp_required=True)

        with pytest.raises(controllers.AuthVerifyError):
            self._auth("alice", PIN + "000000")
