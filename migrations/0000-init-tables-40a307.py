# Copyright 2016 Eugene Frolov <eugene@frolov.net.ru>
# Copyright 2025 Genesis Corporation
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
        self._depends = []

    @property
    def migration_id(self):
        return "40a307b3-fdcc-46d8-bc81-1e2a53ac59e4"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        expressions = [
            # """
            # CREATE TABLE "users" (
            #     "uuid" CHAR(36) PRIMARY KEY,
            #     "username" VARCHAR(256) NOT NULL UNIQUE,
            #     "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
            #     "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            # );
            # """,
            # """
            # CREATE TABLE "networks" (
            #     "uuid" CHAR(36) PRIMARY KEY,
            #     "name" VARCHAR(256) NOT NULL UNIQUE,
            #     "subnet" cidr,
            #     "gateway" inet,
            #     "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
            #     "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            # );
            # """,
            # """
            # CREATE TABLE "ipam" (
            #     "uuid" CHAR(36) PRIMARY KEY,
            #     "network_id" uuid REFERENCES networks(uuid) ON DELETE RESTRICT,
            #     "address" inet,
            #     "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
            #     "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            # );
            # CREATE UNIQUE INDEX ON ipam (network_id, address);
            # """,
            """
            CREATE TYPE "certificates_status" AS ENUM ('ACTIVE', 'DISABLED');
            """,
            """
            CREATE SEQUENCE serial_number;
            """,
            """
            CREATE TABLE "certificates" (
                "uuid" UUID PRIMARY KEY,
                "name" VARCHAR(36),
                "common_name" VARCHAR(256) NOT NULL UNIQUE,
                "status" certificates_status NOT NULL DEFAULT 'ACTIVE',
                "user_id" VARCHAR(36),
                "key" VARCHAR(4096),
                "req" VARCHAR(4096),
                "cert" VARCHAR(4096),
                "serial" numeric UNIQUE,
                "address_offset" int UNIQUE,
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            );
            """,
        ]

        for expression in expressions:
            session.execute(expression)

    def downgrade(self, session):
        views = []

        tables = [
            "certificates",
            # "ipam",
            # "users",
        ]

        for view in views:
            self._delete_view_if_exists(session, view)

        for table in tables:
            self._delete_table_if_exists(session, table)

        session.execute('DROP TYPE IF EXISTS "certificates_status" CASCADE;')
        session.execute("DROP SEQUENCE IF EXISTS serial_number;")


migration_step = MigrationStep()
