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
    APP="$DEST/NetScan.app"
    # NetScan's update button passes its own bundle: the copy that was started is the one to replace.
    # Only an .app in a writable folder, so rm -rf below never hits anything else.
    case "${NETSCAN_TARGET:-}" in
        *.app) if [ -w "$(dirname "$NETSCAN_TARGET")" ]; then APP=$NETSCAN_TARGET; fi ;;
    esac
    pkill -x NetScan 2>/dev/null || true
    rm -rf "$APP"
    ditto "$TMP/NetScan.app" "$APP"
    # curl sets no quarantine flag; this only matters if the zip came through a browser before
    xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

    echo "NetScan ist installiert: $APP"
    echo "Beim ersten Scan nach dem Zugriff auf das lokale Netzwerk gefragt? Erlauben, sonst findet NetScan nichts."
    open "$APP"
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
    EXE="$BIN/netscan"
    # NetScan's update button passes its own path: the copy that was started is the one to replace
    case "${NETSCAN_TARGET:-}" in
        */netscan) if [ -w "$(dirname "$NETSCAN_TARGET")" ]; then EXE=$NETSCAN_TARGET; fi ;;
    esac
    pkill -x netscan 2>/dev/null || true
    # copy, then rename: replaces the file even if an old NetScan is still running
    cp "$TMP/NetScan/netscan" "$EXE.new"
    chmod 755 "$EXE.new"
    mv -f "$EXE.new" "$EXE"
    cp "$TMP/NetScan/netscan.png" "$ICONS/netscan.png"
    cat > "$DATA/applications/netscan.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=NetScan
GenericName=Netzwerkscanner
Comment=IP- und Port-Scanner mit Geräteerkennung
Exec="$EXE"
Icon=netscan
Terminal=false
Categories=Network;System;Monitor;
StartupWMClass=netscan
DESKTOP
    command -v update-desktop-database >/dev/null && update-desktop-database "$DATA/applications" 2>/dev/null || true
    command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "$DATA/icons/hicolor" 2>/dev/null || true

    echo "NetScan ist installiert: $EXE (im Anwendungsmenü unter «NetScan»)"
    if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
        nohup "$EXE" >/dev/null 2>&1 &
    fi
}

case "$(uname -s)" in
    Darwin) install_macos ;;
    Linux) install_linux ;;
    *) echo "Dieses Skript ist für macOS und Linux. Windows: siehe README."; exit 1 ;;
esac
