#!/bin/sh
set -e

mkdir -p /etc/permesi
chmod 0750 /etc/permesi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

echo "Permesi installed."
echo "Copy /usr/share/doc/permesi/permesi.env.example to /etc/permesi/permesi.env and edit it."
echo "Then run: systemctl enable --now permesi.service"
