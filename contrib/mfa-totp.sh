#!/bin/bash
# Helper to generate a TOTP code for testing.
#
# Usage:
#   ./mfa-totp.sh <secret>
#
# Arguments:
#   <secret>  The plaintext TOTP secret in Base32 format (as displayed in the UI during enrollment).
#             Example: JBSWY3DPEHPK3PXP

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <base32-secret>"
    echo ""
    echo "Example:"
    echo "  $0 JBSWY3DPEHPK3PXP"
    exit 1
fi

if ! command -v oathtool &> /dev/null; then
    echo "Error: oathtool is not installed. Install it via 'sudo apt install oath-toolkit' or equivalent."
    exit 1
fi

SECRET="$1"

# oathtool -b expects base32 input
# -s 30: 30-second time step (standard)
# -d 6: 6 digits (standard)
oathtool --totp -b -s 30 -d 6 "$SECRET"