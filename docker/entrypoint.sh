#!/bin/sh
# Credential bootstrap for the res gateway.
#
# Credentials must be explicit, never generated and printed to logs:
#
#   1. RES_ADMIN_PASSWORD / RES_VIEWER_PASSWORD environment (explicit choice)
#   2. persisted /etc/res/res.credentials (argon2 hashes; survives restarts)
#   3. neither: refuse to start (the gateway fail-closed rule is mirrored here)
#
# docker-compose.yml supplies path 1, so the documented stack still starts
# with a bare `docker compose up -d`.
set -eu

# The image runs as UID 10001. Refuse an explicit `--user 0` override:
# dropping privileges for the DNS data plane is the point of the image.
if [ "$(id -u)" = "0" ]; then
    echo "res-entrypoint: refusing to run as root; use the image's UID 10001 (or a writable bind mount owned by that UID)." >&2
    exit 1
fi

if [ -z "${RES_ADMIN_PASSWORD:-}" ] && [ -z "${RES_VIEWER_PASSWORD:-}" ] \
   && [ ! -f /etc/res/res.credentials ]; then
    echo "res-entrypoint: refusing to start without credentials." >&2
    echo "res-entrypoint: set RES_ADMIN_PASSWORD (and optionally RES_VIEWER_PASSWORD), or mount a persisted /etc/res/res.credentials." >&2
    exit 1
fi

# CMD carries the gateway's flags (e.g. --config ... serve): run them as
# arguments to the res binary, not as a command of their own.
exec res "$@"
