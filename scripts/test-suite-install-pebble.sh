#!/bin/bash
#
# Install Pebble for testing.
#
set -eu

# Download certs and config
mkdir -p /etc/pebble

wget -nv "https://raw.githubusercontent.com/letsencrypt/pebble/v${PEBBLE_VERSION}/test/certs/pebble.minica.pem" -O /etc/pebble/ca.cert.pem
wget -nv "https://raw.githubusercontent.com/letsencrypt/pebble/v${PEBBLE_VERSION}/test/certs/localhost/cert.pem" -O /etc/pebble/cert.pem
wget -nv "https://raw.githubusercontent.com/letsencrypt/pebble/v${PEBBLE_VERSION}/test/certs/localhost/key.pem" -O /etc/pebble/key.pem
wget -nv "https://raw.githubusercontent.com/letsencrypt/pebble/v${PEBBLE_VERSION}/test/config/pebble-config.json" -O /etc/pebble/pebble.json

# Download and install Pebble
wget -nv "https://github.com/letsencrypt/pebble/releases/download/v${PEBBLE_VERSION}/pebble_linux-amd64" -O /usr/local/bin/pebble

chown root:root /usr/local/bin/pebble
chmod 0755 /usr/local/bin/pebble

# Config
sed -i 's/test\/certs\/localhost/\/etc\/pebble/' /etc/pebble/pebble.json

exit 0
