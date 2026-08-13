#!/bin/sh
set -eu

patched=${MAPLE_PATCHED_HTTPAPI:?MAPLE_PATCHED_HTTPAPI is required}
installed=${MAPLE_WINE_HTTPAPI:-/usr/lib/wine/x86_64-windows/httpapi.dll}

if [ ! -f "$patched" ]; then
    printf 'patched Wine HTTP API DLL does not exist: %s\n' "$patched" >&2
    exit 1
fi
if [ ! -f "$installed" ]; then
    printf 'installed Wine HTTP API DLL does not exist: %s\n' "$installed" >&2
    exit 1
fi

mount --bind "$patched" "$installed"
exec "$@"
