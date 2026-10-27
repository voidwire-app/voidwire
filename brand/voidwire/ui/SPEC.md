# Voidwire M1 UI polish: spec

*UI/UX Designer, Oct 11, 2026 (round 2: 1:40 PM CT; round 3: 4:30 PM CT).*

## Changelog

### Round 4: Android design gate (Oct 13, 2026)

The full verdict is in `REVIEW-m11-android.md`.

- **§3.6 Share:** **LAST USED is an overline above the label** inside the gold button, not a trailing tag. Send labels get up to **2 lines**; anything longer uses a middle ellipsis and the full name as `contentDescription` (`screens/24`, `25`).
- **§3.2 Main:** the PC card **Check** button is neutral (`onSurface` content, `outline` border), never gold.

### Round 3: review of the M1.1 build (kit 1.1.1, Oct 11, 2026)

The full calls and the batched fix list for the SE are in **`REVIEW-m11.md`**.

- **Kit:** the `shapes.css` focus selector gets doubled specificity (0,3,0), so component state rules such as `.btn-danger.armed` can't hide the focus ring. `tokens.json` → 1.1.1. Nothing else changed in the generated output. **SE: regenerate after the current build** (only `desktop/ui/shapes.css` differs).
- **Decisions recorded:**
  - **Pair a phone…** is **kept** (no longer proposed).
  - PC lists are **A–Z** (decided).
  - The new desktop setting **Show a notice when a link opens** is **default ON**: host only, cleared when Voidwire quits, disabled while Ask before opening is on (§2.4).
- **Desktop:**
  - The Paired devices/Settings window is now **500×620**, with a scrolling Settings pane and a fixed footer.
  - Pair has new **paused** and **done** states (§2.3; `screens/16`, `17`).
  - Ask before opening copy is trimmed.
  - The Devices note line follows the notice setting.
- **Android:**
  - Main: the wire strip is pinned to the bottom, the empty text is bodyMedium, `THIS PHONE` uses a middle ellipsis (`screens/21`).
  - Scanner: frame, supporting text, full-width Use link.
  - Share: no-PC and no-link states (`screens/18`, `19`); Cancel/Close are muted.
  - Settings: the order is confirmed as Privacy → This phone → Appearance, and there is one dashed NOTHING STORED box.
- **New rules (§4):** name truncation; dismissive actions are never gold.
- **Mocks:** 02, 06 and 13 are updated to the shipped (SPEC) copy. New screens 16–23 and `review-3.png`.

### Round 2 (tokens 1.1.0, Oct 11, 2026)

Nothing was renamed from round 1: every token, CSS variable and Kotlin name from round 1 still exists. Everything below was added.

- **Chamfered corners, used selectively** (§1.6).
  - Cut corners go on primary buttons, cards, the 6-digit code cells, chips, segmented controls and the desktop window header band.
  - Secondary buttons, inputs, toasts, dialogs and switches stay soft. Android secondary buttons drop the pill shape and use 6 dp, the same as desktop.
  - New tokens: `chamfer.{sm,md,lg}` = 4/8/12, `chamferCorners` (the **signature** pair is top-left + bottom-right), `componentShape.*` and `m3Shapes.*`.
  - New generated file: **`shapes.css`** with the `.vw-cut*` utilities, borders and focus rings that follow the cut.
  - Compose: `VoidwireShapes` (same name) now uses `CutCornerShape` for the M3 `small` (chips) and `medium` (cards) slots. New **`VoidwireComponentShapes`** holds the named shapes.
- **Theme setting System / Dark / Light, default System** (§2.6, §3.1). It appears in desktop Settings and Android Settings. Compose gets `ThemeMode` plus the `VoidwireTheme(themeMode)` overload. The existing `VoidwireTheme(darkTheme = …)` is unchanged.
- **Remember last PC** is a new privacy opt-in, **off by default**. With it off, the share sheet lists PCs A–Z, the first one is the gold button, and there is no LAST USED tag (§3.6, §3.7).
- **Decisions recorded:**
  - The desktop diagnostics log is opt-in and off (**decided, M1.1**).
  - "ENCRYPTED · NO ACCOUNT · NO HISTORY" stays on Android Main, with a rule for when NO HISTORY may be shown (§3.2).
  - The branded Windows title bar is **deferred** (not rejected).
  - "Pair a phone…" in Paired devices was still **proposed** (kept in round 3).
- **Repo:** `brand/voidwire/ui/` is committed as the source of truth. The `build_tokens.py` outputs sync into `desktop/ui/` and `android/.../ui/theme/` under a CI check. Output files are now `tokens.css`, `fonts.css`, **`shapes.css`** (new) and `compose/{Color,Type,Theme}.kt`. Keep these names stable.

### Round 1
First pass. It set the palette, type, tokens, fonts and every M1 screen for the M1 UI polish, replacing the initial unstyled Windows window and default Material theme on Android. The design covers every M1 screen. It was mocked from the current code (`desktop/ui/*`, `desktop/src/main.rs`, `android/.../MainActivity.kt`, `ShareActivity.kt`, `RecentSends.kt`) and PLAN.md, so it shows real features and real copy. Anything new is marked **(new)**.

- Review sheets:
  - `screens/review.png`: tray, pair ×2, paired devices, Android main, pair and share, and the forget feedback.
  - `screens/review-2.png`: desktop Settings, Open link?, Android scanner, different-group dialog, Android Settings, and the light variants.
  - Both are also in `design/m1-polish/`.
- Per-screen PNGs (2×): `screens/01…15-*.png`.
- Mock sources (HTML/CSS using these tokens): `design/m1-polish/src/`. To rebuild everything, run `python3 build_sheets.py`.
- Tokens: `tokens.json` is the source. Running `python3 build_tokens.py` writes `tokens.css`, `fonts.css`, `shapes.css` and `compose/{Color,Type,Theme}.kt`.
- Fonts: see `fonts/` and `fonts/FONTS.md` (Space Grotesk + JetBrains Mono, both OFL).

## 0. Hard rules (visible on both sheets)

| # | Rule | How it is met |
|---|---|---|
| R1 | **Dark is the default** unless the OS explicitly says light. The in-app Theme setting (System / Dark / Light) defaults to System | CSS: `:root` holds the dark set. The light set applies only under `@media (prefers-color-scheme: light)` or `[data-theme=light]`. Compose: `voidwireUseDarkTheme()` returns false only for `UI_MODE_NIGHT_NO`, so `UNDEFINED` gives dark. Windows: the WebView2 `prefers-color-scheme` follows `AppsUseLightTheme`. If the value is missing, the result is dark. |
| R2 | Pair and Paired devices windows **open centered** | Build windows with `.center()` and call `w.center()` again in `show_window` before `show()`. This also applies to Open link?. |
| R3 | **Forget gives instant feedback** | The row collapses optimistically when you confirm. A toast confirms. On error the row comes back with the error message. |
| R4 | **Recent sends** is opt-in and **OFF** by default, with no logs unless it is enabled | Android: a Settings switch, off by default. The list exists only in Settings, never on Main, and `ShareBackend.send` writes nothing while the switch is off. Desktop: the diagnostics log is opt-in and off (decided, M1.1; see 2.4). |
| R4b | **Remember last PC** is opt-in and **OFF** | With it off, nothing is stored. PCs are listed A–Z and the first is the gold primary. There is no LAST USED tag (§3.6) |
| R5 | Privacy-first | Show the host only, never the full URL, in prompts and logs. Status such as "Reachable" is in memory only. Nothing new is persisted. |

## 1. Design tokens

All names map 1:1 between platforms:

- A Material 3 `ColorScheme` role `fooBar` is the CSS variable `--vw-color-foo-bar`. For example, `onPrimaryContainer` is `--vw-color-on-primary-container`.
- Extended roles that Material 3 doesn't have are `success`, `warning` (each with on-/container-/onContainer-), `wire`, `relay`, `node`, `plate` and `focusRing`. They use the same CSS pattern. In Compose they are `VoidwireTheme.extended.<role>`.
- Type roles: the Material 3 `Typography` slot `titleMedium` is `--vw-type-title-medium` (shorthand) plus the `-size`, `-line-height`, `-weight`, `-tracking` and `-family` variables. The extra mono roles `codeLarge`, `codeMedium` and `codeSmall` are `VoidwireTheme.code.*` in Compose.
- Spacing is `--vw-space-<n>` in CSS and `VoidwireSpace.s<n>` in Compose. Shapes are `--vw-shape-<m3-shape>` and `MaterialTheme.shapes.*`. Elevation is `--vw-elevation-level<n>` and `VoidwireElevation.level<n>`. Motion is `--vw-motion-*`.

### 1.1 Color (key roles; the full set is in tokens.json)

| Role | Dark (default) | Light | Used for |
|---|---|---|---|
| background / surface | `#070B14` (brand black) | `#F4F6F9` | Window and screen ground |
| surfaceContainerLow / container / high / highest | `#0B111D` / `#0F1624` / `#141D2E` / `#1A2438` | `#F9FAFC` / `#EEF1F5` / `#E8ECF1` / `#E1E6ED` | Caption bar, cards, dialogs, chip and icon wells |
| primary / onPrimary | `#F2C94C` relay gold / `#1A1400` | `#F2C94C` / `#1A1405` (with 1dp `#8C6A00` outline) | **The one primary action per screen** (Pair, Open, Send to <PC>); gold text/brackets on light surfaces use `relay` `#8C6A00` |
| secondary / onSecondary | `#3D8BFF` wire blue / `#021433` | `#1F5FD1` / `#FFFFFF` | Links, progress, `// eyebrow` labels, info chips, scan line |
| secondaryContainer | `#0E2550` | `#D8E5FF` | Tonal buttons (secondary Send targets, Save, Use link) |
| tertiary | `#C9D1DB` node silver | `#4F5A66` | Device names/ids, device icons, mono node tags |
| onSurface / onSurfaceVariant | `#E3E8EE` / `#8E9AAB` | `#0A1020` / `#4F5A66` | Text / secondary text |
| outline / outlineVariant | `#56647A` / `#1E2839` | `#77849A` / `#CBD3DD` | Input and outline-button borders (≥3:1) / card hairlines |
| error / errorContainer | `#FF6B6B` / `#4A1418` | `#BA1A1A` / `#FFDAD6` | Forget, Removed state |
| success (ext) | `#3DDC97` | `#0F7A4D` | Reachable chip, toast check, Listening chip |
| warning (ext) | `#FFA94D` | `#8A4B00` | Different-group dialog, the pairing "only pair a phone you hold" note |
| inverseSurface | `#E3E8EE` | `#141D2E` | Toasts and snackbars |

Contrast was checked with WCAG 2.x. Every text pair listed is ≥ 4.5:1 and outlines are ≥ 3:1. For example, onPrimary on primary is 11.9:1 dark (`#1A1400` on `#F2C94C`) and 11.55:1 light (`#1A1405` on `#F2C94C`, with a 1dp `inversePrimary` `#8C6A00` outline giving 4.64:1 boundary contrast on `#F4F6F9` and 4.24:1 on `#E8ECF1`), gold text/accents on light surfaces (`relay` `#8C6A00`) are 4.64:1–5.03:1, and onSurfaceVariant on surface is 6.9:1 and 6.5:1. **No dynamic color**: Android 12+ wallpaper colors would bring the purple back. **No purple anywhere.**

### 1.2 Type

UI text is Space Grotesk. Codes, hosts, ids, versions and the `// EYEBROW` section labels are JetBrains Mono. That mono layer gives the hacker feel without making body text harder to read.

| Role | Font | Size/line | Weight | Tracking |
|---|---|---|---|---|
| headlineSmall | Space Grotesk | 24/32 | 600 | −0.005em |
| titleLarge | Space Grotesk | 20/28 | 600 | 0 |
| titleMedium | Space Grotesk | 16/24 | 600 | .005em |
| titleSmall | Space Grotesk | 14/20 | 600 | .005em |
| bodyLarge / Medium / Small | Space Grotesk | 16/24, 14/20, 12/16 | 400 | 0 / 0 / .01em |
| labelLarge (buttons) | Space Grotesk | 14/20 | 600 | .02em |
| labelMedium (eyebrows, uppercase) | JetBrains Mono | 11/16 | 500 | .08em |
| labelSmall (chips) | JetBrains Mono | 10/14 | 500 | .08em |
| codeLarge (SAS digits) | JetBrains Mono | 40/48 | 500 | .06em |
| codeMedium / codeSmall | JetBrains Mono | 14/20, 12/16 | 400 | 0 |

Desktop windows use body 14 px as the base (Win11 density). Android uses bodyLarge 16 sp for inputs and bodyMedium for copy.

### 1.3 Spacing, radii, elevation, motion

- **Spacing:** 4-pt grid. `space-1`=4, `2`=8, `3`=12, `4`=16, `5`=20, `6`=24, `8`=32, `10`=40, `12`=48.
  - Window padding: 24–28 px.
  - Android screen padding: 20 dp.
  - Gap between cards: 8. Gap between sections: 16.
- **Radii** (M3 shapes; see §1.6 for which components are chamfered instead):
  - extraSmall 4
  - small 6: desktop buttons and inputs
  - medium 10: icon wells, code boxes
  - large 14: cards, Android buttons
  - extraLarge 20: dialogs and sheets. Android dialogs use 24 (the M3 default for `AlertDialog`)
  - full for chips and pills
- **Elevation:** M3 levels 0–5 (0/1/3/6/8/12 dp). On dark grounds, separate layers with surface tiers and a 1 px `outlineVariant` hairline rather than shadows. Shadows are used only for toasts (level 3) and dialogs (level 5).
- **Motion:**
  - `durationShort` 120 ms: hover and press
  - `durationMedium` 200 ms: row collapse, toast in
  - `durationLong` 320 ms
  - `easingStandard` `cubic-bezier(.2,0,0,1)`
  - Respect `prefers-reduced-motion` and Android "Remove animations": collapse instantly.

### 1.4 Motifs (keep them sparing)

- `// SECTION` eyebrow labels in mono blue.
- A 16 px dot grid (`.bg-grid`, 7% silver) on desktop window grounds only.
- Gold corner brackets around anything you scan or type (the QR, the code boxes).
- LED chips: a 6 px dot with a soft glow, in success, error, info or idle colors.
- The "wire strip" on Android Main: THIS PHONE ─ gold relay ─ YOUR PC, in the C2 Relay colors. It is the only illustration.

Avoid emoji, cartoon art, gradients on text and more than one gold element competing on a screen.

### 1.5 Brand assets (use the real files, never redraw them)

- Window caption icon: `final/windows/app/voidwire-app-{16,32}.png`. It comes from the `.ico` that Tauri already embeds.
- Tray: `final/tauri/icons/tray/tray-{dark,light}-*.png`. This is already wired in `tray_theme.rs`.
- Android top bar: `final/lockups/voidwire-horizontal-for-dark-bg.svg` (and `-for-light-bg`) at 22 dp high, imported as a VectorDrawable. That is above the 20 px minimum for the horizontal lockup.
- Share dialog header: `final/svg/voidwire-mark.svg` at 28 dp. The README says to use the vector master at 64 px and up, and the pixel grids below that. For a 28 dp in-app mark, use the 24-grid pixel drawing `svg/pixel/voidwire-mark-px24.svg`. *(The mock uses the vector; switch it at implementation.)*
- Pair-window title-bar and tray-menu header glyph: `svg/pixel/voidwire-mark-px16.svg`.

### 1.6 Chamfers and sharp angles (round 2)

**The idea:** cut corners mark the things that *act* or *hold identity*. Everything you just *use* stays soft. Use at most one chamfer size per component, and keep the **signature** corners (top-left + bottom-right, a diagonal pair that echoes the relay bar sitting between the wire's two ends) unless the table says otherwise.

| Component | Shape | Size | Corners | CSS | Compose |
|---|---|---|---|---|---|
| Primary button (gold), armed destructive | chamfer | md 8 | signature | `.vw-cut .vw-cut-md .vw-cut-frame` | `VoidwireComponentShapes.primaryButton` |
| Card (device/PC, settings, info, hint) | chamfer | lg 12 | signature | `.vw-cut .vw-cut-lg .vw-cut-frame` | `MaterialTheme.shapes.medium` (Card default) or `.card` |
| 6-digit code cell | chamfer | md 8 | signature | `.vw-cut .vw-cut-frame` | `.codeCell` |
| Chip / status tag | chamfer | sm 4 | all four | `.vw-cut-all .vw-cut-sm` | `MaterialTheme.shapes.small` or `.chip` |
| Segmented control (tabs, Theme) | chamfer container, **sharp** selected segment (0) | sm 4 | signature | `.vw-cut .vw-cut-sm .vw-cut-frame` | `.segmented` |
| Window header band (desktop) | chamfer | lg 12 | bottom-right only | `.vw-cut-be .vw-cut-lg .vw-cut-frame` | `.windowHeader` (desktop only) |
| Camera preview (scanner) | chamfer | lg 12 | signature | `.vw-cut .vw-cut-lg` | `.card` |
| Icon well, QR brackets, wire-strip nodes | **sharp** | radius 2 / 0 | n/a | `--vw-component-icon-well-radius` | `.iconWell` |
| Secondary, outline, tonal and text buttons | rounded | small 6 | n/a | `--vw-component-secondary-button-radius` | `.secondaryButton` |
| Inputs | rounded | small 6 | n/a | `--vw-component-input-radius` | `.input` / `shapes.extraSmall` |
| Toast / snackbar | rounded | medium 10 | n/a | `--vw-component-toast-radius` | `.toast` |
| Dialogs, Share dialog card | rounded | extraLarge 20 (Android dialogs 24) | n/a | `--vw-component-dialog-radius` | `.dialog` / `shapes.extraLarge` |
| Switch | full | n/a | n/a | n/a | M3 default |

**Rules**

1. Chamfer the **primary** action and the containers that hold identity (devices, codes, status). Never chamfer something the user types into, or a transient surface such as a toast or dialog.
2. One gold chamfered element per view. The armed red "Click again to forget" is the only other filled chamfer.
3. Don't nest same-size chamfers corner to corner. A chip inside a card is fine because the sizes differ.
4. **Nothing sharp-and-glowing:** `clip-path` clips `box-shadow`, so chamfered primaries lost the round-1 gold glow. That is intended; don't add it back with filters.
5. **RTL:** Compose `CutCornerShape(topStart, bottomEnd)` mirrors automatically. The CSS uses physical corners, so add `[dir=rtl] .vw-cut { transform: scaleX(-1) }` only if we ever ship an RTL locale (we don't in M1).
6. Forced-colors / High Contrast: `shapes.css` drops the clip and uses a 1 px `CanvasText` border.

**How the CSS works (`shapes.css`)**

- `clip-path: polygon(...)` with the cut size taken from `--vw-cut`. The size classes set it to `--vw-chamfer-{sm,md,lg}`.
- **Borders:** a plain `border` gets clipped at the diagonal, so `.vw-cut-frame` draws the border in layers:
  - the element's background is the **stroke** (`--vw-cut-stroke`)
  - a `::before` inset by `--vw-cut-stroke-width` is the **fill** (`--vw-cut-fill`), with an inner polygon whose cut is reduced by `stroke × 0.414`, so the diagonal stroke matches the straight edges
  - Components set `--vw-cut-fill` / `--vw-cut-stroke`, never `background` / `border`.
  - The element gets `isolation: isolate`, and the pseudo-element uses `z-index: -1`, so content stays on top.
- **Focus:** `outline` would be clipped too. `.vw-cut-frame:focus-visible` swaps the stroke to `--vw-color-focus-ring` at `--vw-focus-ring-width` (2 px), drawn inside the cut. Filled shapes (the primary button) also use `.vw-cut-frame` with stroke = fill, so the blue ring shows on gold. The focused code cell uses a 2 px **gold** stroke because it is the input caret.
- `.vw-cut-be` (bottom-right only) is for the window header band. It is full-bleed under the native caption, with a 56×2 px gold tick at its bottom-left.

**Compose:** `Card(shape = MaterialTheme.shapes.medium, border = BorderStroke(1.dp, outlineVariant))`. `BorderStroke` follows `CutCornerShape` natively, and focus indication uses the same shape. For buttons, use `Button(shape = VoidwireComponentShapes.primaryButton)`; M3 buttons ignore `Shapes`, so pass the shape explicitly. Use `OutlinedButton(shape = VoidwireComponentShapes.secondaryButton)`.

## 2. Desktop (Tauri 2, `desktop/`)

### 2.1 Tray menu (native: change only labels, order, separators and icons)
```
[px16 mark] Voidwire · WORKSTATION · listening ← disabled MenuItem; same text source as node::tooltip
───────────
Pair a phone…                                 ← was "Pair device…"
Paired devices…                               ← was "Paired devices & settings…" → opens DEVICES_WINDOW on the Devices tab
Settings…                                     ← (new item) → same window, Settings tab
───────────
Quit Voidwire                                 ← was "Quit"
```
- Optional icons: use `IconMenuItem` with 16 px monochrome PNGs. If that's any trouble, drop the icons; the labels matter more.
- Header status: use "listening", or "not listening" when `start_error()` is set. Update it with `MenuItem::set_text` whenever the tooltip changes.
- Android copy that says "tray icon → Pair device…" must change to "Pair a phone…" (see ScanScreen).

### 2.2 Window chrome (all windows)
- Keep the **native** title bar and set `.theme(None)` (follow the OS). Don't use custom decorations: native keeps snap, a11y and the close behaviour.
- Caption color: **DEFERRED** (not rejected; revisit after M1.1). Win11 draws the dark caption as `#202020`. The later plan is `DwmSetWindowAttribute(DWMWA_CAPTION_COLOR=35)` with `surfaceContainerLow #0B111D`. `main.rs` has `#![forbid(unsafe_code)]`, so this belongs in the `os-theme` crate if we do it. It's low priority.
- Set the webview background to `#070B14` (`.background_color(...)`, Tauri ≥ 2.1) to avoid a white flash before CSS loads.
- **Centering (R2):**
  ```rust
  WebviewWindowBuilder::new(...).title(title).inner_size(w, h).resizable(false).center()...build()
  // and in the "already exists" branch of show_window, before show():
  let _ = w.center();
  ```
- Sizes (inner):

  | Window | Size | Note |
  |---|---|---|
  | Pair | 440×560 | unchanged |
  | Paired devices/Settings | **500×620** | was 500×560 (round 2) and 480×520; round 3 adds room for the notice row. The Settings pane scrolls; its footer stays fixed |
  | Open link? | 420×260 | unchanged |

### 2.3 Pair window (`pair.html/js`)
- **Scan state** (`screens/02`):
  - eyebrow `// PAIR A PHONE · STEP 1 OF 2`, then headlineSmall "Scan this with your phone".
  - Two numbered steps (mono gold `01`/`02`).
  - The QR at 256 px on a `#F4F6F9` plate (radius 10, padding 14) with gold corner brackets. **Keep dark modules on light for scanners.** Do not put a logo in the QR centre.
  - Expiry: mono "SINGLE USE · EXPIRES IN 1:27" (m:ss) plus a 3 px blue bar that shrinks with the time left.
  - Footer: "Closing this window cancels the code. A new code appears automatically before this one expires." (the SE copy, accepted in round 3)
- **Code state** (`screens/03`):
  - eyebrow `STEP 2 OF 2`, then "Type the code from your phone".
  - A card for the joining phone (name plus a "Connected" info chip).
  - **6 separate digit boxes** in a 3+3 layout. The input is still one `<input maxlength=7>` with `inputmode=numeric`. Render the boxes as an overlay: one hidden input with visual cells, so paste and IME still work. Gold digits; the focused cell has a gold 2 px border.
  - Helper text: "The code proves it is your phone. One try per QR code."
  - A warning note (warning color): "Only pair a phone you are holding. A paired phone can open links on this PC."
  - Actions: Cancel (outline; calls `pair_cancel` then closes) and **Pair** (primary, disabled until 6 digits).
- **Paused state** (round 3, `screens/16`):
  - eyebrow `PAUSED`, title "Pairing paused", and the line "Codes stop after 10 minutes, or while this window is hidden. No code is valid right now."
  - The 256 px QR slot stays in place as a dashed placeholder, so the layout doesn't jump. Its brackets are `outline` colour; gold means a live code only.
  - Inside the slot: a pause icon well, mono `NO ACTIVE CODE`, and a gold **Show a new code** button, **autofocused**.
  - The timer row becomes `PAUSED · NOTHING CAN PAIR`. Footer: "Closing this window cancels pairing."
- **Done state** (round 3, `screens/17`):
  - The title "Paired with <name>" stays **in the header band** (eyebrow `DONE`).
  - Success card: a sharp success icon well, the name, mono "Android · paired <date>" and a `PAIRED` chip.
  - `// NEXT`: two steps that name this PC, then "You can forget it any time in Paired devices."
  - Actions: **Pair another phone** (outline; the former "Show a new QR code") and **Done** (primary).
- **Errors:** the `#msg` text uses `error` color inside an `errorContainer` banner, never raw red on grey.

### 2.4 Paired devices + Settings (one window, two tabs; `devices.html/js`, `screens/04, 05, 06`)
- **Header band** (round 2, all desktop windows): a full-bleed `surfaceContainerLow` band under the native caption. It has a bottom-right lg chamfer, a hairline bottom edge and a gold tick. In Pair it holds the eyebrow and title; in Open link? it holds the eyebrow.
- **Header:** a segmented tab control (Devices | Settings) on the left; the tabs use 8 px horizontal padding and 14 px icons (accepted in review, round 3). On the right: `THIS PC WORKSTATION · 7b57f85a` in mono (`settings_get`).
- **Devices tab:**
  - eyebrow `// PAIRED PHONES · n`.
  - One card per device: a 38 px icon well, the name (titleSmall), and the platform plus paired date in mono `10/11/2026`. Use `toLocaleDateString` only, not the time. The previous line overflowed.
  - **Forget** is an error-outline button with an unlink icon.
  - Under the list, a note line that follows the settings (round 3):
    - notice on: bell icon + "Each link opened without asking shows 'Opened <site> from <phone>'."
    - notice off: bell-off icon + "Links open without a notice. Turn it on in Settings."
    - Ask before opening on: no line
  - A **Pair a phone…** outline button, right-aligned under the note (shipped in M1.1).
  - Empty state: "No phones paired yet." plus the same button.
  - M2 reserves a slot above the list for the "Couldn't check for removals since <time>" warning banner (PROTOCOL §7.1e).
- **Forget, instant feedback (R3):**
  1. The first click arms the button: it turns filled `error`, reads "Click again to forget", and shows a 2 px bar that runs out over 4 s. When the bar runs out, the button disarms. This keeps today's two-click guard and adds the timeout.
  2. On the second click, **remove the row from the DOM immediately**: 200 ms height and opacity collapse, `prefers-reduced-motion`, then decrement the count. Then `await invoke("device_forget")`.
  3. On success, show a bottom toast (inverseSurface): "**Forgot <name>.** Its links are refused until you pair it again." This is the same text as `notify::forgot_text`. It auto-hides after 6 s, can be dismissed with ×, and uses `role=status`.
  4. On error, put the row back in place with the error inline.
  - Also bump `shownKey` so the 3 s poll doesn't redraw the row back. Today the window waits for the poll, which is why Forget felt dead.
- **Settings tab:**
  - `// OPENING LINKS` card with two rows and a hairline between them (round 3; `screens/06`, `20`):
    - **Ask before opening**: a **switch** (not a checkbox), **off by default**. Copy: "Off: links from your paired phones open right away. On: click Open for every link."
    - **Show a notice when a link opens**: switch, **on by default**. Copy: "For links opened without asking: “Opened github.com from Pixel 6 Pro”, so you notice if a paired phone misbehaves. Site only, never the full link. Windows keeps it in Action Center until Voidwire quits."
      - While Ask is on, the row is disabled (38%) with "Not needed while Ask before opening is on: you click Open for every link." It keeps its own stored value.
      - Engineering: the host-only text comes from core. On quit and at start-up, clear our toasts with `ToastNotificationManager::History().Clear(AUMID)`.
      - If that can't ship in M1.1, use the copy "…Windows keeps these in Action Center until you clear them." (rationale in REVIEW-m11.md §C).
  - The Settings pane scrolls (`overflow:auto`); the version/Listening footer sits outside the scroller.
  - `// APPEARANCE` card **(round 2)**: "Theme" with a segmented **System | Dark | Light** control. System is the default. Helper text: "System follows Windows; dark if Windows doesn't say." Behaviour is in §2.6.
  - `// DIAGNOSTICS` card (**decided, M1.1**): "Keep a diagnostics log", switch **off by default**. Copy: "Off: nothing is written to disk. On: start-up, network errors and refused links (phone + reason, never the link) go to a local file you can attach to a bug report. Turning it off deletes the file."
    - Engineering change: today `node::log()` **always** appends to `LOG_FILE`. Gate the file write on a new `diagnostics_log` setting (stderr can stay). Off deletes `*.log` and `*.log.old`.
    - The setting needs a `settings_set_diagnostics` command plus its capability entry. Optionally add "Open log folder" when the switch is on.
  - Footer: mono `VOIDWIRE 0.1.0 · CORE 0.1.0` and a Listening chip (success) or Not listening chip (error).

### 2.5 Open link? prompt (`confirm.html/js`, `screens/07`)
- eyebrow `// INCOMING LINK`.
- The host in mono at 26/34 px, 500 weight (punycode, as today).
- "from <device>" with a phone icon.
- A muted line: "Only the site is shown here. The full link opens in your default browser if you click Open."
- Actions on the right: Dismiss (outline) and **Open** (primary). Open stays disabled for `ARM_MS` = 1 s after any change; the disabled style is 38% opacity.
- Multiple pending links: stack the cards with an 8 px gap, newest at the bottom, and let the window scroll.
- Window behaviour is unchanged: never focused, never on top, flashes the taskbar. Add `.center()`.

### 2.6 Theme setting (desktop)
- **Storage:** `settings.theme` is `"system" | "dark" | "light"`, default `"system"`. `settings_get` returns it, and a new `settings_set_theme { theme }` command (with a `devices` capability entry) stores it.
- **Webview:**
  - Every window sets `document.documentElement.dataset.theme = "dark"|"light"`, or **removes** the attribute for System. `tokens.css` then applies:
    - `[data-theme=dark]` forces dark
    - `[data-theme=light]` forces light
    - with no attribute, `prefers-color-scheme` decides, and the dark `:root` is the fallback when the OS says nothing
  - To avoid a flash, inject the stored value before first paint. Use `WebviewWindowBuilder::initialization_script("document.documentElement.dataset.theme='dark'")`, or nothing for System.
- **Live update:** after `settings_set_theme`, the Rust side emits a `theme-changed` event to all windows. Each window updates `data-theme`.
- **Native caption:** call `window.set_theme(Some(Theme::Dark | Theme::Light))`, or `None` for System, on every window, so the caption matches the content.
- **Tray icon:** it keeps following the *taskbar* theme (`tray_theme.rs`), not this setting. The taskbar is the icon's background.

### 2.7 Desktop CSS plumbing
- Replace `pair.css` with `tokens.css` + `fonts.css` + `shapes.css` + an `app.css` that holds the components (buttons, switch, chip, card, tabs, toast). `design/m1-polish/src/base.css` and `devices.css` are a working reference that can be lifted almost as-is.
- Remove `color-scheme: light dark` from the old CSS. `tokens.css` sets `color-scheme` per mode.
- Focus: show a `:focus-visible` 2 px `--vw-color-focus-ring` outline with a 2 px offset on every control.
- Controls are 32 px high (`--vw-desktop-control-height`). The minimum hit target is 32×32.

## 3. Android (Compose Material 3, `android/app/src/main/`)

### 3.1 Theme plumbing
1. Copy `compose/Color.kt`, `Type.kt` and `Theme.kt` to `java/app/voidwire/android/ui/theme/` (package `app.voidwire.android.ui.theme`), and copy `fonts/android/*.ttf` to `res/font/`.
2. Replace `MaterialTheme { … }` with **`VoidwireTheme(themeMode) { … }`** in `MainActivity` and `ShareActivity`. Don't use `dynamicColorScheme`.
   - `themeMode = ThemeMode.fromKey(prefs("ui").getString("theme_mode", null))`, held in Compose state so changing it in Settings recomposes immediately. `System` uses `voidwireUseDarkTheme()`: dark unless `UI_MODE_NIGHT_NO`.
   - Pre-Compose window background: the XML themes follow the OS. If the user forced Dark or Light, call `window.setBackgroundDrawable(ColorDrawable(background))` with the matching color in `onCreate` before `setContent`, and `enableEdgeToEdge(SystemBarStyle.dark/light(...))` so the status-bar icons match.
3. Manifest themes: dark is the fallback, so there is no white flash and nothing purple before Compose draws.
   - `res/values/themes.xml`:
     ```xml
     <style name="Theme.Voidwire" parent="android:Theme.Material.NoActionBar">
       <item name="android:windowBackground">#FF070B14</item>
       <item name="android:statusBarColor">@android:color/transparent</item>
       <item name="android:navigationBarColor">@android:color/transparent</item>
     </style>
     <style name="Theme.Voidwire.Dialog" parent="android:Theme.Material.Dialog.NoActionBar">
       <item name="android:windowBackground">@android:color/transparent</item>
     </style>
     ```
   - `res/values-notnight/themes.xml`: the same two styles on `android:Theme.Material.Light.NoActionBar` and `...Light.Dialog.NoActionBar`, with `windowBackground #FFF4F6F9`.
   - Point `<application android:theme>` at `@style/Theme.Voidwire` and ShareActivity at `@style/Theme.Voidwire.Dialog`.
4. Call `enableEdgeToEdge()` in both activities. Light or dark system bar icons follow `voidwireUseDarkTheme()`.

### 3.2 Main (`HomeScreen`, `screens/08`)
- **Top bar:** the lockup on the left, and a **Settings** gear `IconButton` on the right (new navigation target `Screen.Settings`).
- **Hint card** (secondary tint): "Share a link from any app and pick **Send to PC**. It opens on your PC right away."
- **This phone row:** mono `THIS PHONE Pixel 6 Pro`, plus "Rename in Settings", a **blue** (`secondary`) `TextButton`, never gold. **The name field moves to Settings.** The name is one line with a **middle ellipsis** (§4), and the label and name are baseline-aligned.
- Empty state (round 3, `screens/21`): "None yet. Pair with a PC to send links to it." in bodyMedium `onSurfaceVariant`.
- `// PAIRED PCS · n` heading, then a Card per PC (surfaceContainer, radius 14, 1 dp outlineVariant border):
  - A 40 dp icon well, the name (titleMedium), and a status line: "Paired", or after Check "Paired · checked just now". The check result is in-memory UI state only.
  - A chip on the right: `REACHABLE` (success) after a good Check. Nothing before a Check.
  - Actions: **Check** (`OutlinedButton`, pill, refresh icon) and **Forget** (`TextButton` in `error` color).
  - **Removed** card: errorContainer tint at 55% over the container, an unlink icon, the `REMOVED` error chip, and only Forget.
- **Pair with a PC:** the one gold `Button`, full width, 48 dp, with a QR icon.
- **Wire strip** card **pinned to the bottom**. Use `BoxWithConstraints` + `Column(verticalScroll, heightIn(min = maxHeight))` + `Spacer(weight(1f))`, so it still scrolls with a long list.
  - Content: sharp-boxed THIS PHONE ─ relay ─ YOUR PC nodes, plus `ENCRYPTED · NO ACCOUNT · NO HISTORY`, each fact with its 14 dp success-colour icon (**decided: keep**).
  - Below it: centred mono `CORE 0.1.1` (uppercase).
  - **NO HISTORY rule:** show the `NO HISTORY` fact only while **every** history-type opt-in is off. Today those are *Keep recent sends* and *Remember last PC*; any future one must be added to this check.
  - If any of them is on, replace that fact with **`HISTORY ON`**: warning color, the `clock` icon, tappable, and it opens Settings → Privacy. Don't simply drop it; the user should see that something is being kept.
  - The other two facts don't change.
- **The Recent sends section and the divider above it are removed** (R4).
- **Forget (R3):** keep the confirm `AlertDialog` ("Forget WORKSTATION?"), restyled with the tokens. On confirm, `pcs = phone.pairedPcs()` updates the list at once. Animate the removal with `AnimatedVisibility` / `animateItem()` and show a `Snackbar`: "Forgot WORKSTATION. This phone stops sending to it." The `status` text line is replaced by the snackbar for Check and Forget results.

### 3.3 Scanner (`ScanScreen`, `screens/09`)
- Top bar with Back and "Pair with a PC".
- Copy: "On the PC: click the Voidwire tray icon → **Pair a phone…** and point the camera at the code."
- Preview at 3:4 with the `card` chamfer and a **1 dp `outlineVariant` border** that follows the cut (round 3; without it the dark preview merges into the background). The soft glow is optional. Overlay a square reticle (gold, 3 dp corner brackets) and a blue scan line. Animate the line top to bottom over 1.6 s, or keep it static if animations are off.
- A caption pill on the preview: `● LOOKING FOR A VOIDWIRE CODE`.
- Under the preview: a 16 dp eye-off icon + "The camera is only used to read this code. Nothing is saved." Denied-permission state: the same text plus "Allow it in Settings → Apps".
- Paste fallback: an `OutlinedTextField` labelled "Can't scan? Paste the pairing link" with `supportingText` "Starts with voidwire:pair?" in codeSmall. The M3 placeholder only shows on focus, which is fine. Then **Use link** as a **full-width, 48 dp** `FilledTonalButton` (enabled only when `looksLikePairing`). The separate Back button is dropped; the top bar has Back.

### 3.4 Different-group warning (`PairState.ConfirmGroupChange`, `screens/10`)
- An `AlertDialog` with:
  - icon: a warning triangle in a `warningContainer` tile
  - title: unchanged ("Join a different device group?" / "Another PC with this name?")
  - text: the existing sentences, plus a mono 2-row table (`NEW GROUP` in warning color, `CURRENT` listing the joined names)
- Buttons: **Cancel stays the filled primary** (confirmButton) and **Join** is a `TextButton` in `warning` color. Back and outside taps cancel. The logic is unchanged.
- The screen behind shows the top bar plus a spinner under the scrim.

### 3.5 Pair code (`PairState.ShowCode`, `screens/11`)
- Step rail `SCAN ✓ — CODE — DONE` (mono labelSmall; done = success, current = primary).
- eyebrow `// TYPE THIS ON THE PC`, then "Enter this code on **WORKSTATION**" (the name in tertiary).
- Six digit cells (50×68 dp, surfaceContainerHigh, radius 12) in 3+3, `VoidwireTheme.code.codeLarge` in primary.
- A `LinearProgressIndicator` (indeterminate, secondary), then "WAITING FOR THE PC…".
- An info card: "The PC asks for this code so only the phone in your hand can pair. Never read it out to anyone."
- Cancel: an outlined full-width button at the bottom.
- Paired state: the success-colored check, "Paired with WORKSTATION", the existing line, and a gold **Done** button. Failed state: an error icon, "Pairing didn't finish", the message, and **Back**.

### 3.6 Share (`ShareActivity`, `screens/12`)
- A dialog card (surfaceContainerHigh, radius 24, padding 22) over the source app.
- Header: the mark (28 dp, px24 drawing), "Send to PC" (titleMedium), and an info chip `LINK OK`.
- URL block (surfaceContainerLowest): the host in titleLarge, and the full link in codeSmall, max 2 lines, ellipsized.
- **Targets (round 2):** list the PCs in a **stable A–Z order** (case-insensitive `Collator`, with the PC id as tie-breaker). The **first** PC, or the only one, is the gold `Button`: 64 dp, `VoidwireComponentShapes.primaryButton`, monitor icon, "Send to <PC>". The others are `FilledTonalButton` at 48 dp with `secondaryButton` shape. **No `LAST USED` tag and no special highlight.**
  - Only when *Remember last PC* is **on**: the last-used PC moves to the top (it becomes the gold one) and gets a `LAST USED` labelSmall **overline above** "Send to <PC>" (round 4; never beside the name, because it truncated the name).
  - With it **off**, `LastPc.set` writes nothing and `LastPc.order` returns the A–Z order. Turning it off deletes the `share` prefs (`last_pc`).
- **Cancel:** a `TextButton`, right-aligned, **muted** (`contentColor = onSurfaceVariant`), never gold.
- **No PCs** (round 3, `screens/18`): keep the header and URL block. Add a dashed row with a monitor icon well, "No PC paired yet" and "Pair one first, then share this link again." Then the gold **Pair with a PC** (opens Main → scanner; the link is not kept) and the muted Cancel.
- **No link** (round 3, `screens/19`):
  - an error chip `NO LINK`
  - titleLarge "No link found"
  - "The shared text doesn't contain an http or https link."
  - a dashed mono line `NOTHING WAS SENT OR SAVED` (never echo the shared text)
  - a muted **Close**
- Disabled look (before the 500 ms TapGate arms) uses the M3 default 38% treatment. **No logic changes** to TapGate or the touch filtering.
- Done: "Sent to WORKSTATION (opened, 63 ms)." with a success check, then finish after 1.5 s (unchanged). Failed: the "Not sent" title in error color, then "Try again: <PC>" buttons.
- **R4:** `CoreShareBackend.send` must call `RecentSends.add(...)` **only if** `RecentSends.enabled(context)`.

### 3.7 Settings **(new screen, `screens/13`)**
- Top bar: Back, "Settings".
- `// PRIVACY` card with two `ListItem`s. Both are **off by default**.
  - **Keep recent sends** (below).
  - **Remember last PC** (round 2). Supporting text: "Puts the PC you last sent to first in the share sheet. Off: PCs in A–Z order, nothing stored." See §3.6.
  - When both are off: **one** dashed box (1 dp `outline`, radius 6, 16 dp eye-off icon + codeSmall `NOTHING ABOUT YOUR SENDS IS STORED`) **inside** the Privacy card under the two rows. This replaces the old second placeholder. Section order (round 3, decided): **Privacy → This phone → Appearance**.
  - "Keep recent sends" details: a `Switch`, off by default. Supporting text: "Off: nothing is stored about the links you send. On: keeps the time, site (host only) and result of your last 20 sends on this phone. Turning it off deletes them."
  - When it is on, the existing mono list and **Clear** appear here, under the switch. This is the only place they appear.
- `// THIS PHONE` card: the name `OutlinedTextField` ("Name shown on your PCs"), then a row with the note "PCs you pair from now on will show this name." and a tonal **Save** on the right (round 3: accepted as built).
- `// APPEARANCE` card (round 2): "Theme" with a `SingleChoiceSegmentedButtonRow` **System | Dark | Light**, using the `segmented` shape and a sharp selected segment with a gold underline. System is the default. Helper text: "System follows Android; dark if it doesn't say." It is stored as `ui/theme_mode`, and changing it recomposes at once.
- About moves to a mono footer line: `VOIDWIRE 0.1.1 · CORE 0.1.1`, **centred and pinned to the bottom** (same pattern as Main).
- Storage: `RecentSends.enabled` is a boolean in the same `recent_sends` prefs, **default false**. Turning it off calls `clear()`.
- **Migration:** on first run of this version, call `RecentSends.clear()` once. Testers already have M1 history and never opted in.

### 3.8 Mapping from the Software Engineer's in-progress `VoidwireTokens.Roles` (android/.../Theme.kt, uncommitted)

The engineer's plumbing uses its own role names, and it uses blue as `primary` with gold as `accent`. In this design **gold is `primary`** (the one main action) and **blue is `secondary`**. To keep the names stable, the simplest path is to adopt the generated `compose/*.kt` as-is, so the names match the CSS 1:1. If the engineer's `Roles` stays, map it like this:

| In-progress role | Token role (dark value) |
|---|---|
| background | background `#070B14` |
| surface | surfaceContainer `#0F1624` |
| surfaceRaised | surfaceContainerHigh `#141D2E` |
| onSurface / onBackground | onSurface `#E3E8EE` |
| muted | onSurfaceVariant `#8E9AAB` |
| border | outlineVariant `#1E2839` (cards); outline `#56647A` (inputs) |
| primary | **primary `#F2C94C` (gold)** |
| accent | **secondary `#3D8BFF` (blue)** |
| danger / onDanger | error `#FF6B6B` / onError `#2D0003` |
| success | success (extended) `#3DDC97` |

The in-progress `RecentSends.enabled/setEnabled/enforce` (off by default, wiped at start-up when off) already matches 3.7, including the migration.

## 4. Component quick reference

**Rules added in round 3**

- **Dismissive actions are never gold.** Cancel, Close and Dismiss use an outline button on desktop and `TextButton(contentColor = onSurfaceVariant)` on Android. The only exception is the different-group dialog (§3.4), where Cancel *is* the safe default.
- **Names and identifiers:**
  - Identifiers in mono rows (desktop `THIS PC`, Android `THIS PHONE`, chips): one line with a **middle ellipsis** that keeps the last 6 characters (`head(n-7) + "…" + tail(6)`; n = 16 on desktop, 18 on Android). The full name goes in `title` / `contentDescription`.
  - Device names in cards: up to 2 lines, then end ellipsis, with a tooltip.
- **Placeholders** ("nothing here"): a dashed 1 dp `outline` box, radius 6, a 16 dp icon and mono codeSmall caps.

| Component | Desktop (CSS) | Android (Compose) |
|---|---|---|
| Primary button | `.btn-primary.vw-cut.vw-cut-md.vw-cut-frame` (fill + stroke = primary, 32 px, chamfer md) | `Button(shape = VoidwireComponentShapes.primaryButton)` (48 dp; 64 dp for the first Send target) |
| Secondary | `.btn-outline` (outline border, radius 6) | `OutlinedButton(shape = .secondaryButton)` (6 dp, no pill) |
| Tonal | `.btn-tonal` | `FilledTonalButton` |
| Destructive | `.btn-danger` outline → `.btn-danger-armed` filled | `TextButton` with error content color |
| Switch | `.switch` 40×22, on = primary | `Switch` (M3 defaults pick up primary/onPrimary) |
| Chip | `.chip.ok/.err/.info/.idle` + `.vw-cut-all.vw-cut-sm` | `AssistChip` / custom `Surface(shape=full)` with a 6 dp LED |
| Card | `.card.vw-cut.vw-cut-lg.vw-cut-frame` (fill container, stroke outlineVariant) | `Card(shape = shapes.medium, colors = surfaceContainer, border = outlineVariant)` |
| Toast | `.toast` (inverseSurface, level 3, bottom of window) | `SnackbarHost` |
| Eyebrow | `.eyebrow` (`// ` + labelMedium, uppercase, secondary) | `Text(style = labelMedium, color = secondary)` with the `"// "` prefix |

## 5. Decisions and open questions

**Decided**

- **Desktop diagnostics log:** opt-in, off by default. It ships in **M1.1**, and turning it off deletes the file.
- **Main facts row** "ENCRYPTED · NO ACCOUNT · NO HISTORY" is **kept**, under the NO HISTORY rule in §3.2.
- **Theme override:** **added** (System / Dark / Light, default System).
- **Branded Windows caption color** (DWM, needs unsafe in `os-theme`): **deferred**, not rejected.
- **Pair a phone…** in Paired devices: **kept** (round 3).
- **PC lists:** A–Z (case-insensitive, id tie-break) whenever Remember last PC is off (round 3).
- **Show a notice when a link opens:** default ON, host only, cleared on quit (round 3; later removed in M1.2).
- **`brand/voidwire/ui/` is committed** as the source of truth, with outputs synced to `desktop/ui/` and the Android theme package under a CI check.

**Still open**

1. **Graphic Artist:** two optional asset asks.
   - (a) monochrome 16 px tray-menu glyphs, if we use `IconMenuItem`
   - (b) a 28 dp share-dialog mark as an Android VectorDrawable from `pixel/voidwire-mark-px24.svg`
2. **Wire-strip claims:** NO HISTORY is now governed by the rule in §3.2. "ENCRYPTED" should still be checked against the M1 transport wording before public builds.
