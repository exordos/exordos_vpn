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
        self._depends = ["0002-add-auth-cache-c3d8f1.py"]

    @property
    def migration_id(self):
        return "7e1a9c4d-3b6f-4a1e-8c5d-9f0b2e6a7d34"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        session.execute('ALTER TABLE "services" ALTER COLUMN "subnets" DROP NOT NULL;')
        session.execute(
            'ALTER TABLE "services" ADD COLUMN "domains" TEXT[] DEFAULT \'{}\';'
        )
        session.execute('ALTER TABLE "services" ADD COLUMN "nexthop" VARCHAR(45);')

    def downgrade(self, session):
        session.execute('ALTER TABLE "services" DROP COLUMN IF EXISTS "nexthop";')
        session.execute('ALTER TABLE "services" DROP COLUMN IF EXISTS "domains";')
        session.execute('ALTER TABLE "services" ALTER COLUMN "subnets" SET NOT NULL;')


migration_step = MigrationStep()
