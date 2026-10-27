Browser extension (MV3) is not started yet. Icons parked for it:

    "icons": { "16": "icons/icon-16.png", "32": "icons/icon-32.png", "48": "icons/icon-48.png", "128": "icons/icon-128.png" },
    "action": { "default_icon": { "16": "toolbar/toolbar-dark-16.png", "32": "toolbar/toolbar-dark-32.png" } }

`toolbar-dark-*` is for dark browser chrome, `toolbar-light-*` for light chrome. Firefox:
`action.theme_icons` (its `light` key means "icon for a dark theme"); Chrome: detect
`prefers-color-scheme` and call `chrome.action.setIcon`.
