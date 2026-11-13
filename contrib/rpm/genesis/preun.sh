#!/bin/sh
set -e

# $1 is the number of installed copies after the transaction: 0 on removal, 1+ on upgrade.
if [ "$1" = "0" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop genesis.service >/dev/null 2>&1 || true
  systemctl disable genesis.service >/dev/null 2>&1 || true
fi
