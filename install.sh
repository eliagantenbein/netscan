#!/bin/sh
# Installs or updates NetScan on macOS:
#   curl -fsSL https://raw.githubusercontent.com/eliagantenbein/netscan/main/install.sh | sh
set -eu

[ "$(uname -s)" = Darwin ] || { echo "Dieses Skript ist für macOS. Windows: siehe README."; exit 1; }

URL=https://github.com/eliagantenbein/netscan/releases/latest/download/NetScan-macOS.zip
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Lade NetScan herunter …"
curl -fsSL "$URL" -o "$TMP/NetScan.zip"
ditto -x -k "$TMP/NetScan.zip" "$TMP"

DEST=/Applications
[ -w "$DEST" ] || { DEST="$HOME/Applications"; mkdir -p "$DEST"; }
pkill -x NetScan 2>/dev/null || true
rm -rf "$DEST/NetScan.app"
ditto "$TMP/NetScan.app" "$DEST/NetScan.app"
# curl sets no quarantine flag; this only matters if the zip came through a browser before
xattr -dr com.apple.quarantine "$DEST/NetScan.app" 2>/dev/null || true

echo "NetScan ist installiert: $DEST/NetScan.app"
echo "Beim ersten Scan nach dem Zugriff auf das lokale Netzwerk gefragt? Erlauben, sonst findet NetScan nichts."
open "$DEST/NetScan.app"
