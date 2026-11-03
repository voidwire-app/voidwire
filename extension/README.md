# Voidwire Browser Extension (M3.2.1)

Send the active tab URL, right-clicked links, selected text, or the PC clipboard to your paired phone through the local Voidwire desktop app.

## Architecture & Privacy
- **100% Local Bridge (`nativeMessaging`):** The extension talks strictly to the local Voidwire desktop binary (`voidwire --native-messaging-host`) over `stdin`/`stdout` and a current-user-only OS pipe (`app.voidwire.native_host`).
- **Send/Status Only (`AUTH-13`):** The bridge only accepts `status`, `send_url`, `send_text`, `send_clipboard`, and `send_file`. No local IPC message can ever open a URL on the PC.
- **Right-click menus:** "Send link / selection / page to Voidwire". With one paired phone these send straight to it; with two or more each item opens a submenu with one entry per phone, so every send names its phone. The desktop app refuses an id-less send while 2+ phones are paired instead of guessing. The phone list lives in memory only and is refreshed from the desktop app on browser start, popup open, and after a failed send.
- **Looks like the app:** `tokens.css`, `shapes.css`, `fonts.css` and `fonts/` are generated from the same design tokens as the desktop UI (`brand/voidwire/ui/build_tokens.py`; do not edit by hand). Dark by default, light only when the OS asks for it.
- **Zero Background Tracking:** Uses only `nativeMessaging`, `contextMenus`, and `activeTab` (no `<all_urls>` content scripts, no background `tabs` history access, no external network connections, and no URL history storage).

## Loading in Chrome / Brave / Microsoft Edge
1. Make sure the Voidwire desktop app (`v0.4.0+`) has been launched at least once so it registers `app.voidwire.native_host` in `HKCU` (Windows) or `~/.config` (Linux).
2. Open `chrome://extensions` (or `brave://extensions` / `edge://extensions`) and enable **Developer mode**.
3. Click **Load unpacked** and select the folder extracted from `Voidwire_<version>_extension-chromium.zip` on the release page (or `extension/` in a source checkout).
   - Because `manifest.json` embeds a deterministic public key, the extension always receives ID `mknbkjlaloblibdffcebiegchmcbmpbm`, matching the pre-registered Native Messaging host manifest automatically.

## Loading in Firefox
Needs Firefox 140 or later (the first with built-in data-use consent; see `data_collection_permissions` in `manifest.firefox.json`).

1. Make sure the Voidwire desktop app (`v0.4.0+`) has been launched at least once.
2. Open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on…**, and select `Voidwire_<version>_extension-firefox.zip` from the release page (which uses `extension@voidwire.app`).

## Store packages
`scripts/build-extension.sh --stores out` builds the Chrome Web Store / Edge Add-ons zip (without `key`), the addons.mozilla.org zip and the AMO source zip, reproducibly. See [STORE-BUILD.md](STORE-BUILD.md).
