#!/bin/bash
# Builds "RO CEI Connector.app" (SwiftUI app + CryptoTokenKit extension) without Xcode.
# Requires only the Command Line Tools.
#
#   ./build.sh                    build into build/
#   ./build.sh install            build, then install into /Applications and register the extension
#   Every build runs the card-free unit tests in Tests/ first.
#   CODESIGN_IDENTITY=<sha1|name> signing identity (default: first Apple Development identity,
#                                 else ad-hoc); CODESIGN_IDENTITY=- forces ad-hoc (Homebrew)
#   VERSION=x.y.z                 version to stamp (default: latest vX.Y.Z tag)
#
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")"

APP_NAME="RO CEI Connector"
OUT=build
APP="$OUT/$APP_NAME.app"
APPEX="$APP/Contents/PlugIns/ROCEIExtension.appex"
SDK=$(xcrun --show-sdk-path)
MIN=27.0
ARCHS=(arm64 x86_64)

IDENTITY=${CODESIGN_IDENTITY:-$(security find-identity -v -p codesigning 2>/dev/null | awk '/Apple Development/{print $2; exit}')}
IDENTITY=${IDENTITY:--}
if [ -z "${VERSION:-}" ] && TAG=$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null); then
  VERSION=${TAG#v}
fi
BUILD_NUMBER=$(git rev-list --count HEAD 2>/dev/null || echo 1)
stamp() {  # stamp version + build number into an Info.plist
  if [ -n "${VERSION:-}" ]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$1"
  fi
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD_NUMBER" "$1"
}

rm -rf "$APP" "$OUT/obj"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APPEX/Contents/MacOS" "$APPEX/Contents/Resources" "$OUT/obj"

CFLAGS=(-isysroot "$SDK" -fobjc-arc -fmodules -O2 -Wall -Wextra -Wno-unused-parameter -Werror -Wdeprecated -Wdeprecated-declarations -Wdeprecated-implementations -Wpartial-availability)
CARD_SRC=(Shared/CEICard/CEICard.m Shared/CEICard/CEICard+TKSmartCard.m)

echo "==> unit tests"
clang "${CFLAGS[@]}" -mmacosx-version-min=$MIN Tests/CEICardTests.m Shared/CEICard/CEICard.m \
  -framework Foundation -o "$OUT/obj/cei-unit"
"$OUT/obj/cei-unit" > "$OUT/obj/cei-unit.log" || { cat "$OUT/obj/cei-unit.log"; exit 1; }
tail -1 "$OUT/obj/cei-unit.log"

echo "==> cei-test (diagnostic tool)"
clang "${CFLAGS[@]}" -mmacosx-version-min=$MIN Tools/cei-test.m "${CARD_SRC[@]}" \
  -framework Foundation -framework CryptoTokenKit -framework Security -o "$OUT/cei-test"
cat > "$OUT/obj/cei-test.entitlements" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.smartcard</key><true/></dict></plist>
PLIST
codesign -f -s "$IDENTITY" -o runtime --timestamp=none --entitlements "$OUT/obj/cei-test.entitlements" "$OUT/cei-test" 2>/dev/null

echo "==> extension"
for a in "${ARCHS[@]}"; do
  clang "${CFLAGS[@]}" -arch "$a" -mmacosx-version-min=$MIN \
    "${CARD_SRC[@]}" ROCEIExtension/ROCEIToken.m ROCEIExtension/ROCEITokenSession.m \
    -framework Foundation -framework CryptoTokenKit -framework Security \
    -Wl,-e,_NSExtensionMain -o "$OUT/obj/ROCEIExtension-$a"
done
lipo -create "$OUT"/obj/ROCEIExtension-* -output "$APPEX/Contents/MacOS/ROCEIExtension"
cp ROCEIExtension/Info.plist "$APPEX/Contents/Info.plist"
stamp "$APPEX/Contents/Info.plist"
cp ROCEIExtension/AppIcon.icns "$APPEX/Contents/Resources/"
python3 -I Tools/xcstrings.py Shared/Localizable.xcstrings "$APPEX/Contents/Resources" >/dev/null

echo "==> app"
for a in "${ARCHS[@]}"; do
  for f in "${CARD_SRC[@]}"; do
    clang "${CFLAGS[@]}" -arch "$a" -mmacosx-version-min=$MIN -c "$f" -o "$OUT/obj/$(basename "$f" .m)-$a.o"
  done
  swiftc -sdk "$SDK" -target "$a-apple-macos$MIN" -O -parse-as-library -swift-version 6 -warnings-as-errors \
    -import-objc-header ROCEIConnector/BridgingHeader.h \
    ROCEIConnector/ROCEIApp.swift ROCEIConnector/CardModel.swift ROCEIConnector/ContentView.swift \
    "$OUT"/obj/*-"$a".o \
    -framework CryptoTokenKit -framework Security \
    -o "$OUT/obj/app-$a"
done
lipo -create "$OUT"/obj/app-arm64 "$OUT"/obj/app-x86_64 -output "$APP/Contents/MacOS/$APP_NAME"
cp ROCEIConnector/Info.plist "$APP/Contents/Info.plist"
stamp "$APP/Contents/Info.plist"
cp ROCEIConnector/AppIcon.icns "$APP/Contents/Resources/"
python3 -I Tools/xcstrings.py Shared/Localizable.xcstrings "$APP/Contents/Resources" >/dev/null
printf 'APPL????' > "$APP/Contents/PkgInfo"

echo "==> sign"
codesign -f -s "$IDENTITY" -o runtime --timestamp=none \
  --entitlements ROCEIExtension/ROCEIExtension.entitlements "$APPEX"
codesign -f -s "$IDENTITY" -o runtime --timestamp=none \
  --entitlements ROCEIConnector/ROCEIConnector.entitlements "$APP"
codesign --verify --deep --strict "$APP"
echo "built $APP (version ${VERSION:-unversioned} build $BUILD_NUMBER, signed with ${IDENTITY/#-/ad-hoc identity})"

if [ "${1:-}" = "install" ]; then
  echo "==> install"
  DEST="/Applications/$APP_NAME.app"
  pkill -f "$DEST/Contents/MacOS" 2>/dev/null || true
  # Stage next to the destination and swap with one rename, so LaunchServices never sees the
  # extension disappear (a delete-then-copy races with plugin discovery and unregisters it).
  STAGE="/Applications/.$APP_NAME.staging.app"
  rm -rf "$STAGE"
  ditto "$APP" "$STAGE"
  if [ -d "$DEST" ]; then
    OLD="/Applications/.$APP_NAME.old.app"
    rm -rf "$OLD"
    mv "$DEST" "$OLD" && mv "$STAGE" "$DEST" && rm -rf "$OLD"
  else
    mv "$STAGE" "$DEST"
  fi
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$DEST"
  pluginkit -a "$DEST/Contents/PlugIns/ROCEIExtension.appex"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pluginkit -m -p com.apple.ctk-tokens | grep -q com.alxrxs.rocei.connector.extension && break
    sleep 1
    pluginkit -a "$DEST/Contents/PlugIns/ROCEIExtension.appex"
  done
  pluginkit -m -p com.apple.ctk-tokens | grep -q com.alxrxs.rocei.connector.extension \
    || { echo "extension did not register" >&2; exit 1; }
  pluginkit -e use -i com.alxrxs.rocei.connector.extension
  echo "installed $DEST"
fi
