#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${1:-$HERE/bin}"
CC="${CC:-x86_64-w64-mingw32-gcc}"
OBJDUMP="${OBJDUMP:-x86_64-w64-mingw32-objdump}"
mkdir -p "$OUTDIR"

"$CC" -shared -O2 -s -fno-ident -Wall -Wextra \
    -Wl,--no-insert-timestamp \
    "$HERE/src/cng_shim.c" \
    -o "$OUTDIR/cng_dump.dll" -lkernel32

"$CC" -municode -O2 -s -fno-ident -Wall -Wextra -Wno-cast-function-type \
    -static-libgcc -Wl,--no-insert-timestamp \
    "$HERE/src/lsass_cng.c" \
    -o "$OUTDIR/lsass_cng.exe" -lkernel32 -ladvapi32 -lsecur32

echo "--- artifacts ---"
ls -l "$OUTDIR/cng_dump.dll" "$OUTDIR/lsass_cng.exe"
sha256sum "$OUTDIR/cng_dump.dll" "$OUTDIR/lsass_cng.exe"

echo "--- shim exports (contract: exactly GetKeyStorageInterface) ---"
"$OBJDUMP" -p "$OUTDIR/cng_dump.dll" | grep 'GetKeyStorageInterface' | sed 's/^ *\t/  /'
n="$("$OBJDUMP" -p "$OUTDIR/cng_dump.dll" | grep -c 'GetKeyStorageInterface')"
if [ "$n" -lt 1 ]; then
    echo "FAIL: GetKeyStorageInterface export missing" >&2
    exit 1
fi
echo "GetKeyStorageInterface present (ok)"

echo "--- trigger imports ---"
"$OBJDUMP" -p "$OUTDIR/lsass_cng.exe" | grep -E "DLL Name"
