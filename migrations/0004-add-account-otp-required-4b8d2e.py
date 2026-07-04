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
        self._depends = ["0003-add-service-nexthop-domains-7e1a9c.py"]

    @property
    def migration_id(self):
        return "4b8d2e6f-1c9a-4d7b-b3e5-8a0f4c2d9e61"

    @property
    def is_manual(self):
        return False

    def upgrade(self, session):
        session.execute(
            'ALTER TABLE "accounts" ADD COLUMN "otp_required" BOOLEAN '
            "NOT NULL DEFAULT TRUE;"
        )

    def downgrade(self, session):
        session.execute('ALTER TABLE "accounts" DROP COLUMN IF EXISTS "otp_required";')


migration_step = MigrationStep()
