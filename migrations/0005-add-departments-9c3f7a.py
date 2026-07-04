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
        self._depends = ["0004-add-account-otp-required-4b8d2e.py"]

    @property
    def migration_id(self):
        return "9c3f7a2b-5e8d-4f61-a9c4-1d7b0e3a8f52"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        expressions = [
            """
            CREATE TABLE "departments" (
                "uuid" UUID PRIMARY KEY,
                "name" VARCHAR(255) NOT NULL UNIQUE,
                "description" VARCHAR(255) DEFAULT '',
                "parent" UUID REFERENCES departments(uuid),
                "network_access_tags" TEXT[] DEFAULT '{}',
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE TABLE "account_departments" (
                "uuid" UUID PRIMARY KEY,
                "account" UUID NOT NULL REFERENCES accounts(uuid)
                    ON DELETE CASCADE,
                "department" UUID NOT NULL REFERENCES departments(uuid)
                    ON DELETE CASCADE,
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                UNIQUE (account, department)
            );
            """,
            """
            CREATE INDEX idx_departments_updated_at
                ON departments(updated_at);
            """,
            """
            CREATE INDEX idx_account_departments_updated_at
                ON account_departments(updated_at);
            """,
        ]
        for expression in expressions:
            session.execute(expression)

    def downgrade(self, session):
        session.execute('DROP TABLE IF EXISTS "account_departments";')
        session.execute('DROP TABLE IF EXISTS "departments";')


migration_step = MigrationStep()
