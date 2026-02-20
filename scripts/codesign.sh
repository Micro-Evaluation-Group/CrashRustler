#!/bin/bash
# Sign exc_handler with the com.apple.security.get-task-allow entitlement.
#
# Usage: ./scripts/codesign.sh [binary_path]
#   Defaults to target/release/exc_handler if no path given.

set -euo pipefail

BINARY="${1:-target/release/exc_handler}"
ENTITLEMENTS="entitlements/exc_handler.entitlements"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ ! -f "$REPO_ROOT/$ENTITLEMENTS" ]; then
    echo "error: entitlements file not found: $ENTITLEMENTS" >&2
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "error: binary not found: $BINARY" >&2
    echo "Run 'cargo build --release' first." >&2
    exit 1
fi

# Detect signing identity
IDENTITY=$(security find-identity -p codesigning -v 2>/dev/null \
    | grep -oE '[0-9A-F]{40}' \
    | head -1)

if [ -z "$IDENTITY" ]; then
    echo "No codesigning identity found — binary will remain unsigned."
    echo "To sign, install a Developer ID or self-signed certificate in your keychain."
    exit 0
fi

echo "Signing $BINARY with identity $IDENTITY..."
codesign --entitlements "$REPO_ROOT/$ENTITLEMENTS" --force --sign "$IDENTITY" "$BINARY"

echo ""
echo "Verifying signature:"
codesign -dvvv "$BINARY" 2>&1
