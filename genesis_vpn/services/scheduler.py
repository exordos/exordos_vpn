#    Copyright 2025 Genesis Corporation.
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

import datetime
import logging

from gcl_looper.services import basic
from restalchemy.common import contexts


LOG = logging.getLogger(__name__)


class SchedulerService(basic.BasicService):

    def __init__(self, offset_days, **kwargs):
        self._ctx = contexts.Context()
        self.offset_days = offset_days
        super().__init__(**kwargs)

    def _iteration(self):
        start_delta = datetime.timedelta(days=self.offset_days)
        delta = datetime.datetime.now() - start_delta

        with self._ctx.session_manager() as s:
            rowcount = s.execute(
                """\
update certificates set address_offset=NULL where status='DISABLED' and address_offset is not null and updated_at < %s""",
                (delta,),
            ).rowcount
        if rowcount > 0:
            LOG.info("Cleaned up %i unused address_offsets", rowcount)
