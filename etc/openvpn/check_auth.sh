#!/bin/bash
#    Copyright 2026 Genesis Corporation.
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

# OpenVPN auth-user-pass-verify script (via-file mode).
# Calls the exordos_vpn auth endpoint to verify PIN + OTP.
#
# File format (via-file): line 1 = username, line 2 = password

AUTH_ENDPOINT="http://127.0.0.1:8082/v1/auth/verify"

readarray -t lines < "$1"

username="${lines[0]}"
password="${lines[1]}"

# Escape special characters for JSON
username=$(echo "$username" | sed 's/"/\\"/g')
password=$(echo "$password" | sed 's/"/\\"/g')

response=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$AUTH_ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"account_name\":\"${username}\",\"password\":\"${password}\"}" \
  --connect-timeout 2 \
  --max-time 5)

if [ "$response" = "200" ]; then
    exit 0
else
    exit 1
fi
