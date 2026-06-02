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

from restalchemy.storage.sql import migrations


class MigrationStep(migrations.AbstarctMigrationStep):
    def __init__(self):
        self._depends = ["0001-add-networks-b9f4e2.py"]

    @property
    def migration_id(self):
        return "c3d8f1a2-4b5e-6c7d-8e9f-0a1b2c3d4e5f"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        session.execute(
            """
            CREATE TABLE "account_auth_cache" (
                "uuid" UUID PRIMARY KEY,
                "account" UUID NOT NULL REFERENCES accounts(uuid) ON DELETE CASCADE,
                "auth_cache_hash" VARCHAR(64),
                "auth_cache_expires_at" TIMESTAMP(6),
                UNIQUE ("account")
            );
            """
        )

    def downgrade(self, session):
        session.execute('DROP TABLE IF EXISTS "account_auth_cache";')


migration_step = MigrationStep()
