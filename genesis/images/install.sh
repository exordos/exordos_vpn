#!/usr/bin/env bash

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

set -eu
set -x
set -o pipefail

[[ "$EUID" == 0 ]] || exec sudo -s "$0" "$@"

SERVER_NAME=server

GC_PATH="/opt/genesis_vpn"
GC_CFG_DIR=/etc/genesis_vpn
VENV_PATH="$GC_PATH/.venv"

GC_PG_USER="genesis_vpn"
GC_PG_PASS="pass"
GC_PG_DB="genesis_vpn"

SYSTEMD_SERVICE_DIR=/etc/systemd/system/

apt update
apt install -y \
    postgresql \
    libev-dev \
    python3.14-venv \
    python3-dev

# Default creds for genesis notification services
sudo -u postgres psql -c "CREATE ROLE $GC_PG_USER WITH LOGIN PASSWORD '$GC_PG_PASS';"
sudo -u postgres psql -c "CREATE DATABASE $GC_PG_USER OWNER $GC_PG_DB;"

# Install service
mkdir -p $GC_CFG_DIR
cp "$GC_PATH/etc/genesis_vpn/genesis_vpn.conf" $GC_CFG_DIR/
cp "$GC_PATH/etc/genesis_vpn/logging.yaml" $GC_CFG_DIR/
cp "$GC_PATH/etc/genesis_vpn/client_config.j2" $GC_CFG_DIR/

mkdir -p "$VENV_PATH"
python3 -m venv "$VENV_PATH"
source "$GC_PATH"/.venv/bin/activate
pip install pip --upgrade
pip install -r "$GC_PATH"/requirements.txt
pip install -e "$GC_PATH"

# Apply migrations
ra-apply-migration --config-dir "$GC_CFG_DIR/" --path "$GC_PATH/migrations"
deactivate

# Create links to venv
ln -sf "$VENV_PATH/bin/genesis-vpn-user-api" "/usr/bin/genesis-vpn-user-api"
ln -sf "$VENV_PATH/bin/genesis-vpn-server-agent" "/usr/bin/genesis-vpn-server-agent"
ln -sf "$VENV_PATH/bin/genesis-vpn-scheduler" "/usr/bin/genesis-vpn-scheduler"
ln -sf "$VENV_PATH/bin/genesis-vpn-import-certs" "/usr/bin/genesis-vpn-import-certs"
ln -sf "$VENV_PATH/bin/genesis-vpn-cli" "/usr/bin/genesis-vpn-cli"

# Install Systemd service files
cp "$GC_PATH/etc/systemd/genesis-vpn-user-api.service" $SYSTEMD_SERVICE_DIR
cp "$GC_PATH/etc/systemd/genesis-vpn-server-agent.service" $SYSTEMD_SERVICE_DIR
cp "$GC_PATH/etc/systemd/genesis-vpn-scheduler.service" $SYSTEMD_SERVICE_DIR

# Enable genesis notification services
systemctl enable \
    genesis-vpn-user-api \
    genesis-vpn-server-agent \
    genesis-vpn-scheduler

# TODO: move next part into `bootstrap`

# For silent non-interactive mode
export EASYRSA_BATCH=1

# Install packages
apt update
apt install openvpn openvpn-dco-dkms easy-rsa -y

# Prepare configs
make-cadir /etc/openvpn/easy-rsa

# Init server
cd /etc/openvpn/easy-rsa
export EASYRSA_CERT_EXPIRE=3650
./easyrsa init-pki
./easyrsa --days=3650 build-ca nopass
./easyrsa gen-req $SERVER_NAME nopass
./easyrsa gen-dh

./easyrsa sign-req server $SERVER_NAME
openvpn --genkey secret ta.key

cp ta.key pki/dh.pem pki/ca.crt "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/


cat $GC_PATH/etc/sysctl.conf >> /etc/sysctl.conf

cp "$GC_PATH/etc/openvpn/$SERVER_NAME.conf" "/etc/openvpn/"

systemctl enable "openvpn@$SERVER_NAME"


mkdir /etc/openvpn/ccd/

# To create client config, use genesis-vpn-cli
