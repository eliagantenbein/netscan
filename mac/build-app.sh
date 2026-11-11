#!/bin/sh
# Builds NetScan.app on a Mac.
# Needs: Rust (https://rustup.rs) and the Xcode command line tools (`xcode-select --install`).
set -e
cd "$(dirname "$0")/.."

cargo build --release

APP=target/NetScan.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp target/release/netscan "$APP/Contents/MacOS/NetScan"

# NSLocalNetworkUsageDescription: since macOS 15 the system silently blocks local network access without it
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>NetScan</string>
    <key>CFBundleDisplayName</key><string>NetScan</string>
    <key>CFBundleIdentifier</key><string>local.netscan</string>
    <key>CFBundleExecutable</key><string>NetScan</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>0.2.0</string>
    <key>CFBundleVersion</key><string>2</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>NetScan durchsucht das lokale Netzwerk nach Geräten und offenen Ports.</string>
    <key>NSBonjourServices</key>
    <array><string>_device-info._tcp</string></array>
</dict>
</plist>
PLIST

# ad-hoc signature so Gatekeeper accepts the locally built app
codesign --force --deep --sign - "$APP" >/dev/null 2>&1 || true
echo "Fertig: $APP  (nach /Programme ziehen oder direkt öffnen)"
