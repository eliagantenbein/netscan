#!/bin/sh
# Installs or updates NetScan on macOS and Linux:
#   curl -fsSL https://raw.githubusercontent.com/eliagantenbein/netscan/main/install.sh | sh
set -eu

RELEASE=https://github.com/eliagantenbein/netscan/releases/latest/download
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

install_macos() {
    echo "Lade NetScan herunter …"
    curl -fsSL "$RELEASE/NetScan-macOS.zip" -o "$TMP/NetScan.zip"
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
}

# Per user, no root: binary in ~/.local/bin, icon and menu entry under ~/.local/share (XDG standard paths)
install_linux() {
    [ "$(uname -m)" = x86_64 ] || { echo "NetScan gibt es für Linux nur für x86_64 (dieser Rechner: $(uname -m))."; exit 1; }
    echo "Lade NetScan herunter …"
    curl -fsSL "$RELEASE/NetScan-linux-x86_64.tar.gz" | tar -xz -C "$TMP"

    BIN="$HOME/.local/bin"
    DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
    ICONS="$DATA/icons/hicolor/256x256/apps"
    mkdir -p "$BIN" "$ICONS" "$DATA/applications"
    pkill -x netscan 2>/dev/null || true
    # copy, then rename: replaces the file even if an old NetScan is still running
    cp "$TMP/NetScan/netscan" "$BIN/.netscan.new"
    chmod 755 "$BIN/.netscan.new"
    mv -f "$BIN/.netscan.new" "$BIN/netscan"
    cp "$TMP/NetScan/netscan.png" "$ICONS/netscan.png"
    cat > "$DATA/applications/netscan.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=NetScan
GenericName=Netzwerkscanner
Comment=IP- und Port-Scanner mit Geräteerkennung
Exec="$BIN/netscan"
Icon=netscan
Terminal=false
Categories=Network;System;Monitor;
StartupWMClass=netscan
DESKTOP
    command -v update-desktop-database >/dev/null && update-desktop-database "$DATA/applications" 2>/dev/null || true
    command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "$DATA/icons/hicolor" 2>/dev/null || true

    echo "NetScan ist installiert: $BIN/netscan (im Anwendungsmenü unter «NetScan»)"
    if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
        nohup "$BIN/netscan" >/dev/null 2>&1 &
    fi
}

case "$(uname -s)" in
    Darwin) install_macos ;;
    Linux) install_linux ;;
    *) echo "Dieses Skript ist für macOS und Linux. Windows: siehe README."; exit 1 ;;
esac
