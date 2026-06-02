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

from restalchemy.storage.sql import migrations

LOG = logging.getLogger(__name__)


class MigrationStep(migrations.AbstarctMigrationStep):
    def __init__(self):
        self._depends = ["0000-init-tables-40a307.py"]

    @property
    def migration_id(self):
        return "b9f4e2c1-8a3d-4f6e-9b2c-2d7e4a1f0c83"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        session.execute(
            """
            CREATE TABLE "networks" (
                "uuid" UUID PRIMARY KEY,
                "name" VARCHAR(255) NOT NULL UNIQUE,
                "description" VARCHAR(255) DEFAULT '',
                "subnets" TEXT[] NOT NULL,
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            );
            """
        )
        session.execute(
            "CREATE INDEX idx_networks_updated_at ON networks(updated_at);"
        )

        LOG.warn("If you had any data - don't forget to set subnets for DEFAULT network!")

        default_uuid = str(uuid.uuid4())
        session.execute(
            'INSERT INTO "networks" (uuid, name, description, subnets, created_at, updated_at) '
            "VALUES (%s, %s, %s, %s, NOW(), NOW())",
            (default_uuid, "default", "Default VPN network", []),
        )

        # Add network FK column (nullable initially so we can back-fill).
        session.execute(
            'ALTER TABLE "accounts" ADD COLUMN "network" UUID REFERENCES networks(uuid);'
        )

        # Assign all existing accounts to the default network.
        session.execute('UPDATE "accounts" SET "network" = %s', (default_uuid,))

        # Make non-nullable now that all rows are filled.
        session.execute(
            'ALTER TABLE "accounts" ALTER COLUMN "network" SET NOT NULL;'
        )

        # Drop old single-column unique constraint on address_offset.
        session.execute(
            'ALTER TABLE "accounts" DROP CONSTRAINT IF EXISTS "accounts_address_offset_key";'
        )

        # Per-network uniqueness: (network, address_offset).
        session.execute(
            'CREATE UNIQUE INDEX "accounts_network_offset_unique" '
            'ON "accounts"("network", "address_offset");'
        )

    def downgrade(self, session):
        session.execute('DROP INDEX IF EXISTS "accounts_network_offset_unique";')
        session.execute('ALTER TABLE "accounts" DROP COLUMN IF EXISTS "network";')
        # Restore best-effort unique constraint (may fail if duplicate offsets exist).
        try:
            session.execute(
                'ALTER TABLE "accounts" ADD CONSTRAINT "accounts_address_offset_key" '
                "UNIQUE (address_offset);"
            )
        except Exception:
            pass
        session.execute('DROP TABLE IF EXISTS "networks";')


migration_step = MigrationStep()
