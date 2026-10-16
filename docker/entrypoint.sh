#!/bin/sh
# First-run credential bootstrap for the res gateway.
#
# The stack must start with a bare `docker-compose up -d` (no env file), so
# credentials are never required at interpolation time. Precedence:
#
#   1. RES_ADMIN_PASSWORD / RES_VIEWER_PASSWORD environment (explicit choice)
#   2. persisted /etc/res/res.credentials (argon2 hashes; survives restarts)
#   3. neither: generate a random one-time admin password, export it for this
#      process only, and print it once to stderr (docker logs). The binary
#      persists the hash; subsequent starts take path 2 and keep the password.
#
# There are no hardcoded credentials in the image or repository.
set -eu

if [ -z "${RES_ADMIN_PASSWORD:-}" ] && [ -z "${RES_VIEWER_PASSWORD:-}" ] \
   && [ ! -f /etc/res/res.credentials ]; then
    pw=$(head -c 24 /dev/urandom | base64 | tr -d '\n')
    export RES_ADMIN_PASSWORD="$pw"
    echo "res-entrypoint: no password configured; generated one-time admin password for user 'admin': $pw" >&2
    echo "res-entrypoint: only its argon2 hash is persisted (/etc/res/res.credentials); set RES_ADMIN_PASSWORD to choose your own." >&2
fi

# CMD carries the gateway's flags (e.g. --config ... serve): run them as
# arguments to the res binary, not as a command of their own.
exec res "$@"
