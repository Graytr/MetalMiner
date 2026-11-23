# Releasing Metal Miner

A release is the app in a disk image (it opens to the app next to a shortcut to Applications, to drag it
onto) and a zip, both signed with a Developer ID, notarized by Apple, and attached to a GitHub release. The
Mac App Store isn't an option: App Review Guideline 3.1.5(ii) doesn't allow apps that mine on the device.

## One-time setup

1. **An Apple Developer Program membership** ([developer.apple.com/programs](https://developer.apple.com/programs),
   $99 a year). The signature names the team that signed, and macOS shows it as the app's developer, so sign
   with the team you want named.
2. **A Developer ID Application certificate** in your login keychain. In Xcode: Settings → Accounts → your
   Apple ID → your team → Manage Certificates → + → Developer ID Application. Only the team's Account Holder
   can create one. Check it's there:

       security find-identity -v -p codesigning

   It lists `Developer ID Application: Your Name (TEAMID)`; the 10 characters in brackets are your Team ID.
3. **Notarization credentials**, saved in your keychain once. Create an app-specific password at
   [account.apple.com](https://account.apple.com) (Sign-In and Security → App-Specific Passwords), then run
   this and paste the password when asked:

       xcrun notarytool store-credentials metalminer --apple-id YOU@EXAMPLE.COM --team-id TEAMID

4. **The GitHub repository.** Create an empty repository on github.com (no README, license or .gitignore:
   the project has its own), then push both long-lived branches:

       git remote add origin https://github.com/YOUR-NAME/MetalMiner.git
       git push -u origin master develop

   GitHub asks you to sign in on the first push: with HTTPS, use a personal access token as the password,
   or sign in once with GitHub Desktop or `gh auth login`. Until the first release `master` is empty, so
   set the default branch to `develop` (Settings → General → Default branch). A private repository's
   releases can only be downloaded by people you give access to; make it public when it's for everyone.

## Releasing before there's a Developer ID

`./release.sh` without `DEVELOPER_ID` makes the same disk image and zip with an ad-hoc signature.
It runs on any Apple silicon Mac, but macOS warns the first time it's opened, and people have to allow it
once (README, Install). Publish it as a pre-release. When the certificate arrives, build the same tag
signed and notarized, and replace both files on that release.

## Branches

- `master`: released versions only, each tagged (`v0.1.0`, ...).
- `develop`: the next release. Features and fixes branch off it (`feature/...`, `bugfix/...`) and merge
  back with `git merge --no-ff`.

## Each release

1. On `develop`, set the version in `Sources/App/Info.plist`: `CFBundleShortVersionString` (for example
   `0.1.0`) and `CFBundleVersion` (one more than last time). Run every test, then commit:

       ./test.sh --gpu

2. Merge into `master` and tag it:

       git checkout master
       git merge --no-ff develop -m "Release 0.1.0"
       git tag -a v0.1.0 -m "Metal Miner 0.1.0"

3. Build, sign, notarize and staple, from `master`, with Metal Miner quit (the release rebuilds the app in
   `.build/all`). Apple checks the app and then the disk image, a few minutes each:

       DEVELOPER_ID="Developer ID Application: Your Name (TEAMID)" NOTARY_PROFILE=metalminer ./release.sh

   This leaves `dist/Metal-Miner-<version>.dmg` and `.zip`. If notarization fails, `xcrun notarytool log <id>
   --keychain-profile metalminer` says why.
4. Check it the way a user gets it: open the disk image, drag the app somewhere new and open it. macOS
   should open it without a warning, and `spctl -a -t exec -vv "Metal Miner.app"` should say
   `source=Notarized Developer ID`.
5. Publish: push the branches and the tag, then on GitHub draft a release from the tag, attach the disk
   image and the zip, and write what changed.

       git push origin master develop --tags

6. Back to work on `develop`:

       git checkout develop
