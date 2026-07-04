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
import uuid

from exordos_vpn.dm import models


def _dept(name, parent=None, tags=None):
    return models.Department(
        name=name,
        parent=parent.uuid if parent else None,
        network_access_tags=tags or [],
    )


def _link(account_uuid, department):
    """AccountDepartment stand-in: the tag helpers only read
    .account.uuid / .department.uuid."""
    return types.SimpleNamespace(
        account=types.SimpleNamespace(uuid=account_uuid),
        department=department,
    )


def test_effective_tags_own_only():
    dept = _dept("solo", tags=["a", "b"])

    assert models.department_effective_tags([dept]) == {dept.uuid: {"a", "b"}}


def test_effective_tags_inherit_ancestors():
    root = _dept("org", tags=["vpn-basic"])
    mid = _dept("engineering", parent=root, tags=["git"])
    leaf = _dept("backend", parent=mid, tags=["prod"])

    effective = models.department_effective_tags([root, mid, leaf])

    assert effective[root.uuid] == {"vpn-basic"}
    assert effective[mid.uuid] == {"vpn-basic", "git"}
    assert effective[leaf.uuid] == {"vpn-basic", "git", "prod"}


def test_effective_tags_cycle_does_not_hang():
    """A parent cycle (only creatable via manual DB edits) must degrade to
    the union of the cycle members' tags, not an infinite loop."""
    a = _dept("a", tags=["ta"])
    b = _dept("b", parent=a, tags=["tb"])
    a.parent = b.uuid

    effective = models.department_effective_tags([a, b])

    assert effective[a.uuid] == {"ta", "tb"}
    assert effective[b.uuid] == {"ta", "tb"}


def test_effective_tags_missing_parent_is_ignored():
    orphan = _dept("orphan", tags=["t"])
    orphan.parent = uuid.uuid4()

    assert models.department_effective_tags([orphan]) == {orphan.uuid: {"t"}}


def test_granted_tags_union_across_departments():
    root = _dept("org", tags=["vpn-basic"])
    eng = _dept("engineering", parent=root, tags=["git"])
    fin = _dept("finance", tags=["1c"])
    alice, bob = uuid.uuid4(), uuid.uuid4()

    granted = models.department_granted_tags(
        [root, eng, fin],
        [_link(alice, eng), _link(alice, fin), _link(bob, root)],
    )

    assert granted == {
        alice: {"vpn-basic", "git", "1c"},
        bob: {"vpn-basic"},
    }


def test_granted_tags_no_links():
    assert models.department_granted_tags([_dept("d", tags=["t"])], []) == {}
