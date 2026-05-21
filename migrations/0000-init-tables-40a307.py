# Copyright 2016 Eugene Frolov <eugene@frolov.net.ru>
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
        self._depends = []

    @property
    def migration_id(self):
        return "40a307b3-fdcc-46d8-bc81-1e2a53ac59e4"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        expressions = [
            """
            CREATE SEQUENCE serial_number;
            """,
            """
            CREATE TYPE "accounts_status" AS ENUM ('ACTIVE', 'DISABLED');
            """,
            """
            CREATE TYPE "accounts_auth_type" AS ENUM (
                'password_only', 'cert_and_password'
            );
            """,
            """
            CREATE TYPE "otp_devices_status" AS ENUM ('ACTIVE', 'DISABLED');
            """,
            """
            CREATE TYPE "otp_devices_otp_type" AS ENUM ('totp');
            """,
            """
            CREATE TABLE "accounts" (
                "uuid" UUID PRIMARY KEY,
                "user_id" VARCHAR(36) NOT NULL,
                "account_name" VARCHAR(256) NOT NULL UNIQUE,
                "auth_type" accounts_auth_type NOT NULL
                    DEFAULT 'password_only',
                "status" accounts_status NOT NULL DEFAULT 'ACTIVE',
                "pin_length" INTEGER NOT NULL DEFAULT 10,
                "address_offset" int UNIQUE,
                "pin_salt" VARCHAR(256),
                "pin_hash" VARCHAR(256) NOT NULL,
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE TABLE "otp_devices" (
                "uuid" UUID PRIMARY KEY,
                "user_id" VARCHAR(36) NOT NULL,
                "name" VARCHAR(256) DEFAULT '',
                "otp_secret" VARCHAR(1024) NOT NULL,
                "otp_type" otp_devices_otp_type NOT NULL DEFAULT 'totp',
                "status" otp_devices_status NOT NULL DEFAULT 'ACTIVE',
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            );
            """,
            """
            CREATE TABLE "account_otp_devices" (
                "uuid" UUID PRIMARY KEY,
                "account" UUID NOT NULL REFERENCES accounts(uuid)
                    ON DELETE CASCADE,
                "otp_device" UUID NOT NULL REFERENCES otp_devices(uuid)
                    ON DELETE CASCADE,
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                UNIQUE (account, otp_device)
            );
            """,
            """
            CREATE TABLE "certificates" (
                "uuid" UUID PRIMARY KEY,
                "user_id" VARCHAR(36),
                "key" VARCHAR(4096),
                "req" VARCHAR(4096),
                "cert" VARCHAR(4096),
                "serial" numeric UNIQUE,
                "account" UUID NOT NULL REFERENCES accounts(uuid)
                    ON DELETE CASCADE,
                "created_at" TIMESTAMP(6) NOT NULL DEFAULT NOW(),
                "updated_at" TIMESTAMP(6) NOT NULL DEFAULT NOW()
            );
            """,
        ]

        for expression in expressions:
            session.execute(expression)

    def downgrade(self, session):
        tables = [
            "certificates",
            "account_otp_devices",
            "otp_devices",
            "accounts",
        ]

        for table in tables:
            self._delete_table_if_exists(session, table)

        session.execute('DROP TYPE IF EXISTS "otp_devices_otp_type" CASCADE;')
        session.execute('DROP TYPE IF EXISTS "otp_devices_status" CASCADE;')
        session.execute('DROP TYPE IF EXISTS "accounts_auth_type" CASCADE;')
        session.execute('DROP TYPE IF EXISTS "accounts_status" CASCADE;')
        session.execute("DROP SEQUENCE IF EXISTS serial_number;")


migration_step = MigrationStep()
