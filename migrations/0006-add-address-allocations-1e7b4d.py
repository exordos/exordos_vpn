# Copyright 2025-2026 Genesis Corporation
#
# All Rights Reserved.
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

import logging
import uuid

import netaddr
from restalchemy.storage.sql import migrations

LOG = logging.getLogger(__name__)


def _ip_for_offset(subnets, offset):
    """Resolve (ip, netmask) for a sequential offset — mirrors
    Network.ip_for_offset (offsets start at 2; each subnet contributes
    size-3 client slots, filled in order). Returns (None, None) when the
    offset can't be resolved (no subnets / beyond capacity)."""
    remaining = offset - 2
    for subnet_str in subnets or []:
        subnet = netaddr.IPNetwork(str(subnet_str))
        capacity = max(subnet.size - 3, 0)
        if remaining < capacity:
            return str(subnet.network + remaining + 2), str(subnet.netmask)
        remaining -= capacity
    return None, None


class MigrationStep(migrations.AbstarctMigrationStep):
    def __init__(self):
        self._depends = ["0005-add-departments-9c3f7a.py"]

    @property
    def migration_id(self):
        return "1e7b4d3c-8a29-4f07-b6d1-2c9e5a0f7b84"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        expressions = [
            # Append-only ownership history for address offsets (client
            # IPs). Snapshot columns only (no FKs) so the trail survives
            # deletion of the account or network it refers to.
            """
            CREATE TABLE "address_allocations" (
                "uuid" UUID PRIMARY KEY,
                "network_uuid" UUID NOT NULL,
                "network_name" VARCHAR(255) NOT NULL,
                "address_offset" INT NOT NULL,
                "ip" VARCHAR(64) NOT NULL,
                "netmask" VARCHAR(64),
                "account_uuid" UUID NOT NULL,
                "account_name" VARCHAR(255) NOT NULL,
                "user_id" VARCHAR(255) NOT NULL,
                "allocated_at" TIMESTAMP(6) NOT NULL,
                "released_at" TIMESTAMP(6),
                "release_reason" VARCHAR(32),
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE INDEX idx_address_allocations_account_uuid
                ON address_allocations(account_uuid);
            """,
            """
            CREATE INDEX idx_address_allocations_user_id
                ON address_allocations(user_id);
            """,
            """
            CREATE INDEX idx_address_allocations_ip
                ON address_allocations(ip);
            """,
            """
            CREATE INDEX idx_address_allocations_network_offset
                ON address_allocations(network_uuid, address_offset);
            """,
            """
            CREATE INDEX idx_address_allocations_allocated_at
                ON address_allocations(allocated_at);
            """,
            # Fast lookup of the currently-open span per (network, offset).
            """
            CREATE INDEX idx_address_allocations_open
                ON address_allocations(network_uuid, address_offset)
                WHERE released_at IS NULL;
            """,
        ]
        for expression in expressions:
            session.execute(expression)

        # Back-fill: every account that currently holds an offset owns its
        # IP right now, so open a span for it with allocated_at set to when
        # the account was created (its allocation time). Covers active
        # accounts and disabled ones not yet reclaimed by the scheduler.
        rows = session.execute(
            """
            SELECT a.uuid AS account_uuid,
                   a.account_name,
                   a.user_id,
                   a.address_offset,
                   a.created_at,
                   n.uuid AS network_uuid,
                   n.name AS network_name,
                   n.subnets AS subnets
            FROM accounts a
            JOIN networks n ON n.uuid = a.network
            WHERE a.address_offset IS NOT NULL
            """
        ).fetchall()

        backfilled = 0
        for row in rows:
            ip, netmask = _ip_for_offset(row["subnets"], row["address_offset"])
            if ip is None:
                LOG.warning(
                    "Skip allocation back-fill for account %s: offset %s "
                    "not resolvable in network %s",
                    row["account_uuid"],
                    row["address_offset"],
                    row["network_name"],
                )
                continue
            session.execute(
                """
                INSERT INTO "address_allocations" (
                    uuid, network_uuid, network_name, address_offset,
                    ip, netmask, account_uuid, account_name, user_id,
                    allocated_at, created_at, updated_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
                )
                """,
                (
                    str(uuid.uuid4()),
                    str(row["network_uuid"]),
                    row["network_name"],
                    row["address_offset"],
                    ip,
                    netmask,
                    str(row["account_uuid"]),
                    row["account_name"],
                    row["user_id"],
                    row["created_at"],
                ),
            )
            backfilled += 1

        if backfilled:
            LOG.info("Back-filled %i address allocation spans", backfilled)

    def downgrade(self, session):
        session.execute('DROP TABLE IF EXISTS "address_allocations";')


migration_step = MigrationStep()
