<h1 align="center">
  <picture>
    <source srcset=".docs/images/nydia-leaf-dark.svg" media="(prefers-color-scheme: light)" height="44px" alt="Nydia Logo">
    <img src=".docs/images/nydia-leaf-light.svg" height="44px" alt="Nydia Logo">  
  </picture>
</h1>

<p align="center">
  Fast and lightweight browser extension for decentralized passkey storage on the <a href="https://sia.tech">Sia network</a>.
  <br>
  Hold your passkeys locally with encrypted decentralized backup.
  <br>
  One codebase for Chrome, Firefox and Safari.
</p>

<div align="center">

[![Chrome](https://img.shields.io/badge/WebExtension-Chrome-4285F4?logo=googlechrome&logoColor=white)](https://chrome.google.com/webstore/detail/)
[![Firefox](https://img.shields.io/badge/WebExtension-Firefox-FF7139?logo=firefoxbrowser&logoColor=white)](https://addons.mozilla.org/firefox/addon/)
[![Safari](https://img.shields.io/badge/WebExtension-Safari-006CFF?logo=safari&logoColor=white)](https://apps.apple.com/app/) <br>
[![WebAuthn](https://img.shields.io/badge/Standard-WebAuthn%20%7C%20FIDO2-00B4D8?logo=webauthn&logoColor=white)](https://www.w3.org/TR/webauthn-3/)
[![Passkeys](https://img.shields.io/badge/Authentication-Passkeys-2EA44F?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAzMiAzMiI+PHBhdGggZmlsbD0iI2ZmZmZmZiIgZD0iTTcgNS4yMWEuNzcuNzcgMCAwMS0uNDYtMS4zOEExNS40NiAxNS40NiAwIDAxMTYgMWMyLjY2IDAgNi40OC40NSA5LjUgMi42MmEuNzcuNzcgMCAwMS4xOCAxLjA3Ljc4Ljc4IDAgMDEtMS4wOC4xN0ExNSAxNSAwIDAwMTYgMi41MyAxNCAxNCAwIDAwNy41IDUuMDUuNzQuNzQgMCAwMTcgNS4yMXpNMjguMjMgMTIuMjZhLjc4Ljc4IDAgMDEtLjYzLS4zM0MyNS44NyA5LjQ5IDIyLjc4IDYuMjQgMTYgNi4yNGExNCAxNCAwIDAwLTExLjYzIDUuNy43Ny43NyAwIDAxLTEuMDcuMTcuNzYuNzYgMCAwMS0uMTUtMS4xMUExNS41NCAxNS41NCAwIDAxMTYgNC43MWM1LjYxIDAgOS44MSAyLjA4IDEyLjg0IDYuMzRhLjc3Ljc3IDAgMDEtLjE5IDEuMDcuNzkuNzkgMCAwMS0uNDIuMTR6TTEyLjI4IDMxYS43OC43OCAwIDAxLS43Mi0uNDkuNzUuNzUgMCAwMS40NC0xYzQuMzctMS42OCA3LTUuMTIgNy05LjIxYTIuOCAyLjggMCAwMC0zLTNjLTEuODYgMC0yLjc2IDEtMyAzLjM1YTQuMjcgNC4yNyAwIDAxLTQuNTIgMy44MyA0LjI3IDQuMjcgMCAwMS00LjMyLTQuNTlBMTEuNzEgMTEuNzEgMCAwMTE2IDguMzlhMTIgMTIgMCAwMTEyIDExLjkzIDE4LjY2IDE4LjY2IDAgMDEtMS4zOSA2LjUuNzguNzggMCAwMS0xIC40MS43Ni43NiAwIDAxLS40MS0xIDE3LjI1IDE3LjI1IDAgMDAxLjI3LTUuOTFBMTAuNDUgMTAuNDUgMCAwMDE2IDkuOTJhMTAuMTggMTAuMTggMCAwMC0xMC4zOCAxMCAyLjc3IDIuNzcgMCAwMDIuNzkgMy4wNiAyLjc0IDIuNzQgMCAwMDMtMi40OGMuMzYtMy4xMSAxLjg5LTQuNjkgNC41Ni00LjY5YTQuMzEgNC4zMSAwIDAxNC41MiA0LjU2YzAgNC43NC0zIDguNzItOCAxMC42M0EuOTIuOTIgMCAwMTEyLjI4IDMxek0xOS43NyAzMC4yOGEuODEuODEgMCAwMS0uNTItLjIuNzYuNzYgMCAwMTAtMS4wOCAxMi42MyAxMi42MyAwIDAwMy41NC04LjY4YzAtMS41Ni0uNDgtNi42NS02LjctNi42NWE2LjgzIDYuODMgMCAwMC00Ljk0IDEuODdBNi4xNyA2LjE3IDAgMDA5LjMyIDIwYS43Ny43NyAwIDAxLS43Ny43NmgwQS43Ni43NiAwIDAxNy43OCAyMCA3LjczIDcuNzMgMCAwMTEwIDE0LjQ2YTguMzQgOC4zNCAwIDAxNi0yLjMyYzYuMDggMCA4LjI0IDQuNCA4LjI0IDguMThBMTQuMDkgMTQuMDkgMCAwMTIwLjM0IDMwYS43NS43NSAwIDAxLS41Ny4yOHpNOC42NiAyNy43NGExNC4xNCAxNC4xNCAwIDAxLTEuNTYtLjA5Ljc2Ljc2IDAgMTEuMTctMS41MmMyLjQ5LjI4IDQuNDUtLjE2IDUuODQtMS4zMmE2LjM3IDYuMzcgMCAwMDIuMTItNC41My43NS43NSAwIDAxLjgyLS43MS43OC43OCAwIDAxLjcyLjgxQTcuODkgNy44OSAwIDAxMTQuMDkgMjYgOC4yIDguMiAwIDAxOC42NiAyNy43NHoiLz48L3N2Zz4=)](https://www.w3.org/TR/webauthn-3/)
[![Sia](https://img.shields.io/badge/Storage-Sia%20Network-00C65E?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA1MTIgNTEyIj48ZyBmaWxsPSIjRkZGRkZGIj48cGF0aCBkPSJNMzE2LjYgMjU2djYwLjZIMjU2Yy0zMy41IDAtNjAuNi0yNy4xLTYwLjYtNjAuNnMyNy4xLTYwLjYgNjAuNi02MC42IDYwLjYgMjcuMSA2MC42IDYwLjZtLTU5LjgtMTAxYy01NS44LTEuNy0xMDIuMyA0Mi4yLTEwNCA5Ny45LTEuNyA1NS44IDQyLjIgMTAyLjMgOTcuOSAxMDQgMS44LjEgMy41LjEgNS4zIDBoMTAxdi05OS43YzAtNTUuNi00NC41LTEwMS44LTEwMC4yLTEwMi4yIi8+PHBhdGggZD0iTTM5OC44IDExMy4yQzMyOS43IDQ0LjEgMjIzIDM1LjYgMTQ0LjYgODcuNWMyLjMgMi41IDQuMiA1LjMgNS44IDguMyA3NC40LTQ5LjEgMTc1LjgtNDAuOSAyNDEuMyAyNC41IDc0LjggNzQuOCA3NC44IDE5Ni41IDAgMjcxLjNzLTE5Ni41IDc0LjgtMjcxLjMgMGMtNjUuNS02NS41LTczLjYtMTY2LjgtMjQuNS0yNDEuMy0zLTEuNi01LjgtMy41LTguMy01LjgtNTIgNzguNC00My40IDE4NS4xIDI1LjcgMjU0LjIgNzguOSA3OC45IDIwNi43IDc4LjkgMjg1LjYgMHM3OC43LTIwNi42LS4xLTI4NS41Ii8+PHBhdGggZD0iTTEwMC40IDEwMC40YzcuOS03LjkgMjAuNy03LjkgMjguNiAwIDcuOSA3LjkgNy45IDIwLjcgMCAyOC42LTcuOSA3LjktMjAuNyA3LjktMjguNSAwLTgtOC04LTIwLjctLjEtMjguNiIvPjwvZz48L3N2Zz4=)](https://sia.tech/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

</div>

<div align="center">
    <img src=".docs/images/menu.png" width="320" alt="Nydia menu">
</div>
<br>

## Preparing to build

#### Prerequisites
- Node.js 24+ and npm
- Xcode with command-line tools (Safari only)

Safari build runs on Safari 17+ and macOS 12.0+

## How to build Nydia

1. Clone the repository:
```bash
git clone https://github.com/new0nebit/Nydia-Passkey-Holder.git
cd Nydia-Passkey-Holder
```

2. Install dependencies:
```bash
npm install
```

3. Build the extension for the browser you need:
```bash
npm run build            # all browsers
npm run build:chrome     # → build/chrome
npm run build:firefox    # → build/firefox
npm run build:safari     # → build/safari
```

### Chrome

- Navigate to `chrome://extensions`
- Enable "Developer mode"
- Click "Load unpacked" and select the `build/chrome` directory

### Firefox

- Navigate to `about:debugging#/runtime/this-firefox`
- Click "Load Temporary Add-on"
- Select any file from the `build/firefox` directory

### Safari

1. Build the app:
```bash
xcodebuild \
  -project "app/Nydia Passkey Holder.xcodeproj" \
  -scheme "Nydia Passkey Holder" \
  -configuration Release \
  -derivedDataPath build/xcode \
  DEVELOPMENT_TEAM=
```

2. Launch the app once so Safari registers the extension:
```bash
open "build/xcode/Build/Products/Release/Nydia for Safari.app"
```

3. Enable the extension in Safari:
    - Open Settings
    - Go to `Advanced` and enable "Show features for web developers"
    - Navigate to `Developer`
    - Enable "Allow unsigned extensions"
    - Go to `Extensions` and turn on Nydia: Passkey Holder

## Development

```bash
npm run dev           # rebuild on change
npm run check         # lint + type-check
npm test              # unit and integration tests
npm run debug         # production build that keeps debug logging
npm run analyze       # bundle size report
```

Chrome, Firefox and Safari share one codebase. API adapters live in `src/browser-api/`, browser-specific files in `assets/`, and Safari's native app wrapper in `app/`.

## Sia backup<sup><a href="https://sia.tech"><img src=".docs/images/sia-shard.svg" height="10px" alt="Sia"></a></sup>

1. Install and configure `renterd` following the [official documentation](https://docs.sia.tech/renting/setting-up-renterd).
2. In the extension, configure your `renterd` settings:
    - Server Address
    - Server Port
    - Password
    - Bucket Name
3. Click **Save**, allow access to your server if Nydia asks, then click **Test Connection**.

<div align="center">
    <img src=".docs/images/renterd-settings.png" width="350" alt="Renterd settings">
</div>

## Security and privacy

Nydia is local-first: your passkeys are encrypted with keys derived from your recovery phrase.\
No Nydia account is required. No telemetry. No tracking.

- **Encrypted on your device.** Your passkeys, their details, your `renterd` settings, including the server password, and saved website icons are encrypted locally with AES-256-GCM. Backups are encrypted before they leave your device.
- **Recovery phrase.** During setup, Nydia generates a 12-word recovery phrase on your device or lets you enter an existing Nydia phrase. It creates your encryption key from the phrase locally and stores the key, not the phrase itself. Nydia doesn't send your recovery phrase or encryption key outside your device. To restore your passkeys, you need the phrase and access to the same `renterd` server and bucket, so keep it somewhere safe.
- **Network access.** Nydia communicates with websites when you create a passkey or sign in, and with your chosen `renterd` server for backups. Website icons are optional and off by default. If you turn on **Show website icons** in Settings, Nydia downloads missing icons from Google. These requests send the site's domain and your IP address to Google. You can turn icons off there at any time.

Read the [Privacy Policy](PRIVACY.md) for details.

<br>

<div align="center">
  <a href="https://sia.tech"><picture><source
    srcset=".docs/images/built-on-sia-light.svg"
    media="(prefers-color-scheme: dark)"
  ><img
    src=".docs/images/built-on-sia-dark.svg"
    height="28px"
    alt="Built on Sia"
  ></picture></a>
  &emsp;&emsp;
  <a href="https://sia.tech/grants"><picture><source
    srcset=".docs/images/sia-grant-light.svg"
    media="(prefers-color-scheme: dark)"
  ><img
    src=".docs/images/sia-grant-dark.svg"
    height="72px"
    alt="Supported by a Sia Foundation Grant"
  ></picture></a>
</div>
