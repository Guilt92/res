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

# The image defaults to UID 10001; compose may select another non-root UID.
# Refuse an explicit `--user 0` override: dropping privileges for the DNS data
# plane is the point of the image.
if [ "$(id -u)" = "0" ]; then
    echo "res-entrypoint: refusing to run as root; use the image's non-root UID (or a writable bind mount owned by that UID)." >&2
    exit 1
fi

# Locate the configured file so custom mounts are checked too. The gateway
# persists runtime mutations via temp file + fsync + rename and writes
# res.credentials next to the config, so the directory must be writable by
# this UID. Fail early with an actionable ownership message instead of an
# obscure EACCES from the dashboard later.
config_path=/etc/res/res.toml
prev=
for arg in "$@"; do
    if [ "$prev" = "--config" ]; then
        config_path=$arg
    fi
    case "$arg" in
        --config=*) config_path=${arg#--config=} ;;
    esac
    prev=$arg
done
config_dir=$(dirname "$config_path")
probe="$config_dir/.res-entrypoint-write-test.$$"
if ! (umask 077; : > "$probe") 2>/dev/null; then
    echo "res-entrypoint: config directory $config_dir is not writable by UID $(id -u):GID $(id -g)." >&2
    echo "res-entrypoint: runtime config updates and res.credentials require a writable directory (temp file + atomic rename)." >&2
    echo "res-entrypoint: fix ownership outside the container, then recreate it, for example:" >&2
    echo "  sudo chown -R \"\${RES_UID:-$(id -u)}:\${RES_GID:-$(id -g)}\" ./config" >&2
    echo "  RES_UID=$(id -u) RES_GID=$(id -g) docker compose up -d --force-recreate" >&2
    exit 1
fi
rm -f "$probe"

config_credentials="$config_dir/res.credentials"
if [ -z "${RES_ADMIN_PASSWORD:-}" ] && [ -z "${RES_VIEWER_PASSWORD:-}" ] \
   && [ ! -f "$config_credentials" ]; then
    echo "res-entrypoint: refusing to start without credentials." >&2
    echo "res-entrypoint: set RES_ADMIN_PASSWORD (and optionally RES_VIEWER_PASSWORD), or mount a persisted res.credentials next to the config." >&2
    exit 1
fi

# CMD carries the gateway's flags (e.g. --config ... serve): run them as
# arguments to the res binary, not as a command of their own.
exec res "$@"
