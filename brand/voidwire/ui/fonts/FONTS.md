# Bundled fonts

Both fonts are under the **SIL Open Font License 1.1**, which allows bundling and redistribution in apps (including
commercial ones) as long as the license text ships with them and the fonts aren't sold on their own. Neither font
declares a Reserved Font Name, so the subset files may keep the original family names.

| Font | Use | License | Source | Files here |
|---|---|---|---|---|
| **Space Grotesk** (variable, wght 300–700) | All UI text (titles, body, buttons) | SIL OFL 1.1, `OFL-SpaceGrotesk.txt` | https://github.com/google/fonts/tree/main/ofl/spacegrotesk (upstream: https://github.com/floriankarsten/space-grotesk) | `web/SpaceGrotesk-Variable.latin.woff2` (31 KB), `android/space_grotesk_{regular,medium,semibold,bold}.ttf` (~50 KB each) |
| **JetBrains Mono** (variable, wght 100–800) | Codes (SAS), hosts, device ids, `// EYEBROW` labels, versions | SIL OFL 1.1, `OFL-JetBrainsMono.txt` | https://github.com/google/fonts/tree/main/ofl/jetbrainsmono (upstream: https://github.com/JetBrains/JetBrainsMono) | `web/JetBrainsMono-Variable.latin.woff2` (42 KB), `android/jetbrains_mono_{regular,medium}.ttf` (~61 KB each) |

Downloaded Oct 11, 2026 from `raw.githubusercontent.com/google/fonts/main/ofl/...` (`SpaceGrotesk[wght].ttf`,
`JetBrainsMono[wght].ttf`, and each `OFL.txt`).

Total: about 400 KB (73 KB for desktop, 322 KB for Android).

## How the files were made

- **Desktop (woff2):** `pyftsubset` (fontTools) on the variable fonts, keeping the `wght` axis. Coverage: Basic Latin, Latin-1,
  Latin Extended-A, general punctuation, arrows, `€ ™ • … ● ✓ ✕`. Space Grotesk keeps all OpenType features; JetBrains Mono keeps
  `kern liga calt zero ss01 tnum`. Characters outside the subset (Cyrillic, CJK, emoji in device names) fall back to the
  next family in `--vw-font-sans` / `--vw-font-mono` (Segoe UI / Cascadia Mono on Windows).
- **Android (ttf):** fontTools `varLib.instancer` to static instances (Space Grotesk 400/500/600/700, JetBrains Mono 400/500),
  then subset to the same Latin range. Static files keep Compose simple on minSdk 26. Android falls back to the system font for
  missing glyphs automatically.

To rebuild with more coverage, rerun the same commands on the upstream variable files with a wider `--unicodes`.

## Where they go

- Desktop: copy `web/*.woff2` to `desktop/ui/fonts/web/` and `../fonts.css` + `../tokens.css` to `desktop/ui/`
  (fonts.css paths are relative to itself). Tauri serves them from the app bundle; nothing is fetched at runtime.
- Android: copy `android/*.ttf` to `android/app/src/main/res/font/` (names are already valid resource names).
- Ship both `OFL-*.txt` files with each app's third-party notices (`about.toml` / licenses screen inventory).

## Checksums (sha256)
    1f1e68421686303442557db790d04f65ef4b9f23141503df8cd1d1537b429f03 web/JetBrainsMono-Variable.latin.woff2
    68efd2df44a4438435fe42e497048b4fcbb50cde4837159966ba665b5cd3f1db web/SpaceGrotesk-Variable.latin.woff2
    55945ced83024c60e8bcf90966b6ac2b63b87a19d6c449b2008f798c86732d09 android/jetbrains_mono_medium.ttf
    a31ad6de2d18a9c8c9ecb5bfe40db821524917321296169b46ca55874b4d8f4c android/jetbrains_mono_regular.ttf
    4a559ff1c613ecb37ff1b40f86ee65c41f6f55d5b4f5f7c6c5b0a3981771537a android/space_grotesk_bold.ttf
    80976a4439eda2e02035ee5250aa9646622d79085b3abbec5d140ca5e3624256 android/space_grotesk_medium.ttf
    5b79647d626e7bb846154a89e18439fde5324933a8ae075753c4238873c5e058 android/space_grotesk_regular.ttf
    e338c67a6a430fc408bdcf852afffd911912db06389e05cc3966b5560b090df2 android/space_grotesk_semibold.ttf
