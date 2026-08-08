#!/bin/sh
set -eu

patched=/home/sdancer/ms/downloads/maplestory_classic_wine_prefix/drive_c/windows/system32/httpapi.dll
installed=/usr/lib/wine/x86_64-windows/httpapi.dll

mount --bind "$patched" "$installed"
exec "$@"
