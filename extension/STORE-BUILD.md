# Building the Voidwire browser extension (store review)

This is the README for the source package sent with the add-on for review.

## What's generated and what isn't

- `background.js`, `popup.js`, `popup.html` and `popup.css` are hand-written. They
  aren't bundled, minified or transpiled, and there are no third-party libraries.
- `tokens.css`, `fonts.css` and `shapes.css` are generated from
  `brand/voidwire/ui/tokens.json` by `brand/voidwire/ui/build_tokens.py`. The
  generated files are readable CSS and are checked in.
- The two `.woff2` fonts are Space Grotesk and JetBrains Mono (SIL OFL 1.1),
  copied from `brand/voidwire/ui/fonts/web/`. See `brand/voidwire/ui/fonts/FONTS.md`.
- There's no Node, npm or lockfile: the build uses only the Python 3 standard library.

## Build

Tested on Ubuntu 24.04 with its stock Python 3.12. Any Python 3.8 or later works.

```sh
# Optional: regenerate the CSS and fonts from tokens.json. Writes the same files
# under /tmp/vw-tokens; they must match the copies in extension/.
python3 brand/voidwire/ui/build_tokens.py --root /tmp/vw-tokens
for f in tokens.css fonts.css shapes.css; do cmp extension/$f /tmp/vw-tokens/extension/$f; done

# Build the store packages into out/
python3 scripts/extension_pack.py stores out
cat out/SHA256SUMS
```

`out/voidwire-extension-<version>-firefox-amo.zip` is the file uploaded to
addons.mozilla.org. `out/voidwire-extension-<version>-chromium-store.zip` goes to
the Chrome Web Store and Microsoft Edge Add-ons.

The zips are reproducible: the file order, timestamps (1980-01-01), permissions and
compression level are fixed. The same source gives the same zip, byte for byte,
with the same zlib. To compare contents regardless of zlib version:

```sh
mkdir a b && (cd a && unzip -q ../out/voidwire-extension-*-firefox-amo.zip) \
  && (cd b && unzip -q /path/to/submitted.xpi) && diff -r a b
```

## What the extension does

Voidwire sends a link, selected text or the current tab's address from the browser
to the user's own paired devices. It does that through the Voidwire desktop app on
the same computer, over native messaging (`app.voidwire.native_host`). The
extension makes no network requests itself (`connect-src 'none'`), has no content
scripts or host permissions, and stores nothing.

Data leaves the browser only when the user clicks a send action (toolbar popup or
right-click menu). Then exactly the item they chose goes to the desktop app, which
end-to-end encrypts it to the paired device. The desktop app's `status` reply
lists the paired device names so the user can pick one; it's held in memory only.

Testing needs the Voidwire desktop app (Windows, Linux or macOS beta):
https://voidwire.app/download.html. Without it the popup shows "Voidwire desktop
app is not running". No account or login exists.
