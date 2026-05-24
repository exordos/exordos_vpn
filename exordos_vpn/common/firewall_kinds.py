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

from restalchemy.dm import models
from restalchemy.dm import properties
from restalchemy.dm import types
from restalchemy.dm import types_dynamic


class FirewallKindAny(types_dynamic.AbstractKindModel, models.SimpleViewMixin):
    KIND = "any"

    @staticmethod
    def from_str(kind_str):
        if kind_str == "any":
            return FirewallKindAny()
        raise ValueError(f"Unexpected kind string: {kind_str}")

    def to_str(self):
        return self.KIND


class FirewallKindTcp(types_dynamic.AbstractKindModel, models.SimpleViewMixin):
    KIND = "tcp"

    min_port = properties.property(
        types.Integer(min_value=0, max_value=65535), default=1
    )
    max_port = properties.property(
        types.Integer(min_value=0, max_value=65535), default=65535
    )

    @staticmethod
    def from_str(kind_str):
        if ":" in kind_str:
            _, ports = kind_str.split(":", 1)
            if "-" in ports:
                min_p, max_p = ports.split("-", 1)
                return FirewallKindTcp(min_port=int(min_p), max_port=int(max_p))
            else:
                port = int(ports)
                return FirewallKindTcp(min_port=port, max_port=port)
        else:
            return FirewallKindTcp()

    def to_str(self):
        if self.min_port == 1 and self.max_port == 65535:
            return self.KIND
        if self.min_port == self.max_port:
            return f"{self.KIND}:{self.min_port}"
        return f"{self.KIND}:{self.min_port}-{self.max_port}"


class FirewallKindUdp(types_dynamic.AbstractKindModel, models.SimpleViewMixin):
    KIND = "udp"

    min_port = properties.property(
        types.Integer(min_value=0, max_value=65535), default=1
    )
    max_port = properties.property(
        types.Integer(min_value=0, max_value=65535), default=65535
    )

    @staticmethod
    def from_str(kind_str):
        if ":" in kind_str:
            _, ports = kind_str.split(":", 1)
            if "-" in ports:
                min_p, max_p = ports.split("-", 1)
                return FirewallKindUdp(min_port=int(min_p), max_port=int(max_p))
            else:
                port = int(ports)
                return FirewallKindUdp(min_port=port, max_port=port)
        else:
            return FirewallKindUdp()

    def to_str(self):
        if self.min_port == 1 and self.max_port == 65535:
            return self.KIND
        if self.min_port == self.max_port:
            return f"{self.KIND}:{self.min_port}"
        return f"{self.KIND}:{self.min_port}-{self.max_port}"


FirewallKindSelectorType = types_dynamic.KindModelSelectorType(
    types_dynamic.KindModelType(FirewallKindAny),
    types_dynamic.KindModelType(FirewallKindTcp),
    types_dynamic.KindModelType(FirewallKindUdp),
)


_KIND_MAP = {
    "any": FirewallKindAny,
    "tcp": FirewallKindTcp,
    "udp": FirewallKindUdp,
}


def from_str(kind_str):
    if not kind_str or not kind_str.strip():
        return None
    kind_str = kind_str.strip()
    kind_name = kind_str.split(":")[0] if ":" in kind_str else kind_str
    kind_cls = _KIND_MAP.get(kind_name)
    if kind_cls is None:
        raise ValueError(f"Unknown kind: {kind_name}")
    return kind_cls.from_str(kind_str)


def to_str(kind):
    if kind is None:
        return "-"
    return kind.to_str()
