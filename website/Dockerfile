# voidwire.app static site: nginx (unprivileged) serving dist/site.
# Build the site first (python3 build.py), then: docker build -t voidwire-website .
# No RUN steps, so the multi-arch build needs no emulation.
FROM nginxinc/nginx-unprivileged:1.28-alpine@sha256:7377697a821c131a924a7105fafbe7414db4e9fcc77a6f08f776f33f141ec3f8

COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY nginx/security-headers.conf /etc/nginx/security-headers.conf
COPY --chown=0:0 dist/site/ /srv/site/

USER 101
EXPOSE 8080
STOPSIGNAL SIGQUIT
# Straight to nginx: skips the stock entrypoint scripts, which rewrite
# conf.d/default.conf (not used here) and need a writable filesystem.
ENTRYPOINT ["nginx", "-g", "daemon off;"]
