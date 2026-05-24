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

from restalchemy.api import routes

from exordos_vpn.user_api.api import controllers


class CertificateActions(routes.Action):
    __controller__ = controllers.CertificateController


class CertificateRoute(routes.Route):
    __controller__ = controllers.CertificateController
    __allow_methods__ = [routes.FILTER, routes.CREATE, routes.GET]

    get_ovpn_config = routes.action(CertificateActions)


class AccountRoute(routes.Route):
    __controller__ = controllers.AccountController
    __allow_methods__ = [routes.FILTER, routes.CREATE, routes.GET]


class OtpDeviceRoute(routes.Route):
    __controller__ = controllers.OtpDeviceController
    __allow_methods__ = [routes.FILTER, routes.CREATE, routes.GET]


class AddressesPerUserRoute(routes.Route):
    __allow_methods__ = [routes.FILTER]
    __controller__ = controllers.AddressesPerUserController


class AuthRoute(routes.Route):
    """Handler for /auth/ endpoint - no IAM auth required"""

    __controller__ = controllers.AuthController
    __allow_methods__ = [routes.CREATE]


class ServiceRoute(routes.Route):
    """Handler for /services/ endpoint."""

    __controller__ = controllers.ServiceController
    __allow_methods__ = [
        routes.FILTER,
        routes.CREATE,
        routes.GET,
        routes.DELETE,
        routes.UPDATE,
    ]


class ApiEndpointRoute(routes.Route):
    """Handler for /v1/ endpoint."""

    __controller__ = controllers.ApiEndpointController
    __allow_methods__ = [routes.FILTER]

    certificates = routes.route(CertificateRoute)
    accounts = routes.route(AccountRoute)
    otp_devices = routes.route(OtpDeviceRoute)
    addresses_per_user = routes.route(AddressesPerUserRoute)
    auth = routes.route(AuthRoute)
    services = routes.route(ServiceRoute)
