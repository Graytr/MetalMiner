#!/bin/zsh
# Packages Metal Miner for release: a clean full build, the app signed, then a disk image and a zip in dist/.
# The disk image opens to the app next to a shortcut to Applications, to drag it onto; the zip is there for
# anyone who prefers one.
#
#   ./release.sh
#       Ad-hoc signed. Runs on any Apple silicon Mac, but macOS warns the first time it's opened.
#   DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)" ./release.sh
#       Signed with your Developer ID and the hardened runtime.
#   DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)" NOTARY_PROFILE=metalminer ./release.sh
#       Also notarized by Apple and stapled (the app, then the disk image), so it opens normally on any Mac.
#       NOTARY_PROFILE names notarytool credentials saved in your keychain once, with an app-specific
#       password from account.apple.com:
#         xcrun notarytool store-credentials metalminer --apple-id YOU@EXAMPLE.COM --team-id TEAMID
#
# `security find-identity -v -p codesigning` lists the signing identities in your keychain.
set -euo pipefail
ROOT="${0:A:h}"
DEV="$(xcode-select -p)"
APP="$ROOT/.build/all/Metal Miner.app"
export TMPDIR="$ROOT/.build/release-tmp"   # where the disk image tools keep their temporary files
mkdir -p "$TMPDIR"

if [[ -n "${NOTARY_PROFILE:-}" && -z "${DEVELOPER_ID:-}" ]]; then
  print -u2 "NOTARY_PROFILE needs DEVELOPER_ID too: Apple notarizes only apps signed with a Developer ID"
  exit 1
fi

# Submits a zip or disk image to Apple and waits for the verdict (usually a few minutes). If it isn't
# "Accepted", `xcrun notarytool log <submission id> --keychain-profile "$NOTARY_PROFILE"` says why.
notarize() { "$DEV/usr/bin/notarytool" submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait; }

if /usr/bin/pgrep -f "$APP/Contents/MacOS/MetalMiner" >/dev/null; then
  print -u2 "Metal Miner is running from .build/all; quit it first, since the release rebuilds that app"
  exit 1
fi
rm -rf -- "${APP:?}"   # no stale files from earlier builds in the bundle
"$ROOT/build.sh"

if [[ -n "${DEVELOPER_ID:-}" ]]; then
  /usr/bin/codesign --force --options runtime --timestamp --sign "$DEVELOPER_ID" "$APP"
  /usr/bin/codesign --verify --strict --verbose=2 "$APP"
fi

VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" "$APP/Contents/Info.plist")
mkdir -p "$ROOT/dist"
ZIP="$ROOT/dist/Metal-Miner-$VERSION.zip"
DMG="$ROOT/dist/Metal-Miner-$VERSION.dmg"
rm -f -- "${ZIP:?}" "${DMG:?}"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  notarize "$ZIP"
  "$DEV/usr/bin/stapler" staple "$APP"
  rm -f -- "${ZIP:?}"
  /usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"   # zip again, so the download carries the stapled ticket
fi

# The disk image: the app next to a shortcut to Applications.
STAGE="$ROOT/.build/dmg"
rm -rf -- "${STAGE:?}"
mkdir -p "$STAGE"
/usr/bin/ditto "$APP" "$STAGE/Metal Miner.app"
ln -s /Applications "$STAGE/Applications"
/usr/sbin/diskutil image create from --format ULFO --volumeName "Metal Miner" "$STAGE" "$DMG" >/dev/null
if [[ -n "${DEVELOPER_ID:-}" ]]; then
  /usr/bin/codesign --force --timestamp --sign "$DEVELOPER_ID" "$DMG"
fi
if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  notarize "$DMG"
  "$DEV/usr/bin/stapler" staple "$DMG"
fi

SIGNATURE="ad-hoc"
[[ -n "${DEVELOPER_ID:-}" ]] && SIGNATURE="Developer ID"
[[ -n "${NOTARY_PROFILE:-}" ]] && SIGNATURE="Developer ID, notarized and stapled"
print "packaged ${DMG#$ROOT/} and ${ZIP#$ROOT/} ($SIGNATURE signature)"
