# website/

The voidwire.app static site and its container image.

| Path | What |
|---|---|
| `src/tools/build_site.py` | page generator (from the design prototype); edit copy here |
| `src/site/assets/` | CSS, fonts, icons, the one small script |
| `build.py` | fills release data from GitHub, builds `dist/site/`, runs the content checks |
| `verify.py` | checks a running container (pages, headers, cookies, links, logs) |
| `Dockerfile`, `nginx/` | nginx-unprivileged image, read-only, port 8080 |

The image is published by `.github/workflows/website-image.yml`.
Files starting with `_` (the unbuilt request-form states) are never shipped.
