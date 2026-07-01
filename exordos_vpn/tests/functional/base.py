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

import os

from restalchemy.storage.sql import migrations
from restalchemy.tests.functional import db_utils as ra_db_utils

FIRST_MIGRATION = "0000-init-tables-40a307.py"

MIGRATIONS_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "migrations"
)


class DbTestCase(ra_db_utils.DBEngineMixin):
    """Base class for functional tests that need a real Postgres schema.

    Applies all migrations before each test and rolls them back after,
    so every test starts from an empty, freshly migrated schema.
    """

    @classmethod
    def setup_class(cls):
        cls.init_engine()

    @classmethod
    def teardown_class(cls):
        cls.drop_all_tables(cascade=True)
        cls.destroy_engine()

    @staticmethod
    def get_migration_engine():
        return migrations.MigrationEngine(migrations_path=MIGRATIONS_PATH)

    def setup_method(self):
        self._migrations = self.get_migration_engine()
        self._migrations.rollback_migration(FIRST_MIGRATION)
        self._migrations.apply_migration(self._migrations.get_latest_migration())

    def teardown_method(self):
        self._migrations = self.get_migration_engine()
        self._migrations.rollback_migration(FIRST_MIGRATION)
