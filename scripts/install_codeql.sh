#!/usr/bin/env bash
# Install CodeQL CLI for agies.
# Run manually when network is fast (GitHub release is ~514MB).
#
# Usage:
#   bash scripts/install_codeql.sh
#
# Sets up codeql in ~/.local/share/codeql/ and adds it to PATH.

set -euo pipefail

DEST="${HOME}/.local/share/codeql"
BIN="${DEST}/codeql"
VERSION="v2.25.5"

if [ -f "$BIN" ]; then
    echo "CodeQL already installed at $BIN ($("$BIN" --version 2>&1 | head -1))"
    exit 0
fi

echo "==> Creating $DEST"
mkdir -p "$DEST"

echo "==> Downloading codeql-linux64.zip ($VERSION)..."
# Try gh first, fall back to curl
if command -v gh &>/dev/null; then
    gh release download "$VERSION" --repo github/codeql-cli-binaries --pattern 'codeql-linux64.zip' --dir "$DEST"
else
    curl -L "https://github.com/github/codeql-cli-binaries/releases/download/$VERSION/codeql-linux64.zip" -o "$DEST/codeql-linux64.zip"
fi

echo "==> Extracting..."
unzip -q -o "$DEST/codeql-linux64.zip" -d "$DEST"
rm -f "$DEST/codeql-linux64.zip"

# Make binary executable
chmod +x "$BIN" 2>/dev/null || true

echo "==> Done! CodeQL CLI at $BIN"
"$BIN" version --quiet 2>&1 || echo "(version check skipped if no QL packs cached)"

echo ""
echo "Add to your shell profile:"
echo "  export PATH=\"\$PATH:${DEST}\""
echo ""
echo "Or just run the agies generator — it auto-detects this path."
