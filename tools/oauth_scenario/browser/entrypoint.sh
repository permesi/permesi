#!/bin/sh
set -eu
mkdir -p /root/.pki/nssdb
certutil -N --empty-password -d sql:/root/.pki/nssdb >/dev/null 2>&1
certutil -A -d sql:/root/.pki/nssdb -n permesi-scenario -t 'C,,' -i /scenario-ca.pem >/dev/null 2>&1
exec node /opt/scenario/browser.mjs
