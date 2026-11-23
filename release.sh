#!/bin/zsh
# Packages Metal Miner for release: a clean full build, the app signed, and a zip in dist/.
#
#   ./release.sh
#       Ad-hoc signed zip. Runs on the Mac that built it; Gatekeeper blocks it on other Macs.
#   DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)" ./release.sh
#       Signed with your Developer ID and the hardened runtime.
#   DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)" NOTARY_PROFILE=metalminer ./release.sh
#       Also notarized by Apple and stapled, so it opens normally on any Mac. NOTARY_PROFILE names notarytool
#       credentials saved in your keychain once, with an app-specific password from account.apple.com:
#         xcrun notarytool store-credentials metalminer --apple-id YOU@EXAMPLE.COM --team-id TEAMID
#
# `security find-identity -v -p codesigning` lists the signing identities in your keychain.
set -euo pipefail
ROOT="${0:A:h}"
DEV="$(xcode-select -p)"
APP="$ROOT/.build/all/Metal Miner.app"

if [[ -n "${NOTARY_PROFILE:-}" && -z "${DEVELOPER_ID:-}" ]]; then
  print -u2 "NOTARY_PROFILE needs DEVELOPER_ID too: Apple notarizes only apps signed with a Developer ID"
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
rm -f -- "${ZIP:?}"
/usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"

if [[ -n "${NOTARY_PROFILE:-}" ]]; then
  # Waits for Apple's verdict (usually a few minutes). If it isn't "Accepted", see why with:
  #   xcrun notarytool log <submission id> --keychain-profile "$NOTARY_PROFILE"
  "$DEV/usr/bin/notarytool" submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  "$DEV/usr/bin/stapler" staple "$APP"
  rm -f -- "${ZIP:?}"
  /usr/bin/ditto -c -k --keepParent "$APP" "$ZIP"   # zip again, so the download carries the stapled ticket
fi

SIGNATURE="ad-hoc"
[[ -n "${DEVELOPER_ID:-}" ]] && SIGNATURE="Developer ID"
[[ -n "${NOTARY_PROFILE:-}" ]] && SIGNATURE="Developer ID, notarized and stapled"
print "packaged ${ZIP#$ROOT/} ($SIGNATURE signature)"
