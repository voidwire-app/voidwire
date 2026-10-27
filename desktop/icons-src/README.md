Voidwire app icon masters (C2 Relay, final set from the Graphic Artist,
brand/voidwire/final/ in the artist's working tree).

- `app-icon.png`: `svg/voidwire-app-icon-1024.svg` rendered to 1024 px (reference only).
- `svg/`: the fine vector master (64 px and up) and its on-light/mono variants.
- `svg/pixel/`: the hand-drawn 14/16/24 px grids used for every icon from 16 to 48 px.

The files in `desktop/icons/` are HAND-TUNED: the 16-48 px frames come from the
pixel grids, not from resampling. Do NOT regenerate them with
`cargo tauri icon` (it would resample a single PNG and blur the small sizes).
To change the icon, rebuild the set from the artist's sources
(`brand/voidwire/_build/`: `python3 final_build.py && python3 final_tauri_preview.py`)
and copy `final/tauri/icons/*` over `desktop/icons/`.

`desktop/icons/` layout:
- `32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.ico`, `icon.icns`: bundle icons (tauri.conf.json).
- `tray/`: tray glyphs. `tray-dark-*` for a dark taskbar/panel, `tray-light-*` for a light one,
  `trayTemplate*.png` for the macOS menu bar (template image). Picked at runtime in `src/tray_theme.rs`.
- `linux/hicolor/`: freedesktop icon theme files installed by the .deb/AppImage (`Icon=voidwire`).
- `msix/`: Windows Store/MSIX logos, for a future `Package.appxmanifest` (not used by the NSIS build).
- `Square*Logo.png`, `StoreLogo.png`, `64x64.png`, `icon.png`: Tauri's standard set.
