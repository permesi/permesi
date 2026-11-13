#!/bin/sh
set -e

mkdir -p /etc/genesis
chmod 0750 /etc/genesis

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "Genesis installed."
echo "Copy /usr/share/doc/genesis/genesis.env.example to /etc/genesis/genesis.env and edit it."
echo "Then run: systemctl enable --now genesis.service"
