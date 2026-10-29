# Voidwire Browser Extension (M3.2)

Send the active tab URL, right-clicked links, selected text, or the PC clipboard to your paired phone through the local Voidwire desktop app.

## Architecture & Privacy
- **100% Local Bridge (`nativeMessaging`):** The extension talks strictly to the local Voidwire desktop binary (`voidwire --native-messaging-host`) over `stdin`/`stdout` and a current-user-only OS pipe (`app.voidwire.native_host`).
- **Send/Status Only (`AUTH-13`):** The bridge only accepts `status`, `send_url`, `send_text`, `send_clipboard`, and `send_file`. No local IPC message can ever open a URL on the PC.
- **Zero Background Tracking:** Uses only `nativeMessaging`, `contextMenus`, and `activeTab` (no `<all_urls>` content scripts, no background `tabs` history access, no external network connections, and no URL history storage).

## Loading in Chrome / Brave / Microsoft Edge
1. Make sure the Voidwire desktop app (`v0.4.0+`) has been launched at least once so it registers `app.voidwire.native_host` in `HKCU` (Windows) or `~/.config` (Linux).
2. Open `chrome://extensions` (or `brave://extensions` / `edge://extensions`) and enable **Developer mode**.
3. Click **Load unpacked** and select the extracted `voidwire-extension-chromium` folder (or `extension/` in a source checkout).
   - Because `manifest.json` embeds a deterministic public key, the extension always receives ID `mknbkjlaloblibdffcebiegchmcbmpbm`, matching the pre-registered Native Messaging host manifest automatically.

## Loading in Firefox
1. Make sure the Voidwire desktop app (`v0.4.0+`) has been launched at least once.
2. Open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on…**, and select `voidwire-extension-firefox.zip` (which uses `extension@voidwire.app`).
