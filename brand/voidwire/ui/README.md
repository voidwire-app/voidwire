# Voidwire UI kit (`brand/voidwire/ui`)

| Path | What |
|---|---|
| `tokens.json` | **Source of truth.** Colors (dark + light, M3 role names + extended), type, spacing, shapes, elevation and motion |
| `build_tokens.py` | Generates the files below. Run `python3 build_tokens.py` after editing `tokens.json` |
| `tokens.css` | CSS custom properties `--vw-*`. Dark on `:root`; light under `@media (prefers-color-scheme: light)` and `[data-theme=light]`; `[data-theme=dark]` forces dark |
| `shapes.css` | Chamfer utilities `.vw-cut` (signature TL+BR), `.vw-cut-all`, `.vw-cut-be`, sizes `.vw-cut-sm/md/lg`, and `.vw-cut-frame` (border and focus ring that follow the cut, via `--vw-cut-fill/-stroke`). Rules are in `SPEC.md` §1.6 |
| `fonts.css` | `@font-face` for the bundled woff2 files (paths relative to this file) |
| `compose/Color.kt`, `Type.kt`, `Theme.kt` | `VoidwireDarkColorScheme` / `VoidwireLightColorScheme`, `VoidwireTypography`, `VoidwireShapes` (M3 slots; small/medium chamfered), `VoidwireComponentShapes` (named per-component shapes), `ThemeMode` (System/Dark/Light) + `VoidwireTheme(themeMode) {}`, `VoidwireTheme {}`, `VoidwireTheme.extended`, `VoidwireTheme.code`, `VoidwireSpace`, `VoidwireElevation`. Package `app.voidwire.android.ui.theme` |
| `fonts/` | Space Grotesk + JetBrains Mono (SIL OFL 1.1), as woff2 for desktop and ttf for Android. See `fonts/FONTS.md` |
| `SPEC.md` | Per-screen specs for desktop + Android and implementation notes |

**Sync:** `build_tokens.py` writes both the kit outputs and the app copies (`desktop/ui/{tokens,fonts,shapes}.css` and `android/app/src/main/java/app/voidwire/android/ui/theme/*.kt`). `scripts/gates.sh` (`design-tokens-in-sync`) verifies they are in sync.
