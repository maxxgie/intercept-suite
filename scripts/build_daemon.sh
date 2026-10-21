#!/usr/bin/env bash
# Build the frozen daemon with PyInstaller.
#
# The result lands in dist/intercept/, which the desktop shell ships as
# resources/daemon/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"
if [ ! -x "$PYTHON" ]; then
    PYTHON="$(command -v python3 || true)"
fi
if [ -z "$PYTHON" ]; then
    echo "no python interpreter found; set PYTHON to override" >&2
    exit 1
fi

"$PYTHON" -m pip install --quiet --upgrade pyinstaller >/dev/null 2>&1 || true
"$PYTHON" -m PyInstaller packaging/intercept.spec \
    --noconfirm \
    --distpath dist \
    --workpath build

echo "daemon built at dist/intercept/intercept"
