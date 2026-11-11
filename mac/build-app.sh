#!/bin/sh
# Builds target/NetScan.app (Apple Silicon and Intel in one) and target/NetScan-macOS.zip on a Mac.
# Needs: Rust (https://rustup.rs) and the Xcode command line tools (`xcode-select --install`).
set -e
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
export MACOSX_DEPLOYMENT_TARGET=11.0

rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

APP=target/NetScan.app
rm -rf "$APP" target/NetScan-macOS.zip
mkdir -p "$APP/Contents/MacOS"
lipo -create -output "$APP/Contents/MacOS/NetScan" \
    target/aarch64-apple-darwin/release/netscan target/x86_64-apple-darwin/release/netscan

# Finder icon from assets/icon-mac.png (1024 px, drawn by assets/make-icon.py)
ICONSET=target/NetScan.iconset
rm -rf "$ICONSET"
mkdir -p "$ICONSET" "$APP/Contents/Resources"
for s in 16 32 128 256 512; do
    sips -z $s $s assets/icon-mac.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z $((s * 2)) $((s * 2)) assets/icon-mac.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/NetScan.icns"

# NSLocalNetworkUsageDescription: since macOS 15 the system silently blocks local network access without it
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>NetScan</string>
    <key>CFBundleDisplayName</key><string>NetScan</string>
    <key>CFBundleIdentifier</key><string>io.github.eliagantenbein.netscan</string>
    <key>CFBundleExecutable</key><string>NetScan</string>
    <key>CFBundleIconFile</key><string>NetScan</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$VERSION</string>
    <key>CFBundleVersion</key><string>$VERSION</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSLocalNetworkUsageDescription</key>
    <string>NetScan durchsucht das lokale Netzwerk nach Geräten und offenen Ports.</string>
    <key>NSBonjourServices</key>
    <array><string>_device-info._tcp</string></array>
</dict>
</plist>
PLIST

# ad-hoc signature: Apple Silicon refuses to start unsigned code at all
codesign --force --deep --sign - "$APP"
ditto -c -k --keepParent "$APP" target/NetScan-macOS.zip
echo "Fertig: $APP und target/NetScan-macOS.zip (Version $VERSION)"
