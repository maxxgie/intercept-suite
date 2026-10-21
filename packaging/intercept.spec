# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for the Intercept daemon.

Build with::

    .venv/bin/pyinstaller packaging/intercept.spec --noconfirm

The result is a single executable in ``dist/intercept/`` which the desktop
shell ships as ``resources/daemon/intercept``.
"""

import sys
from pathlib import Path

ROOT = Path(SPECPATH).parent  # noqa: F821 - injected by PyInstaller
SRC = ROOT / "src"

# The example plugins are data, not code, so they travel with the bundle.
datas = [(str(ROOT / "plugins"), "plugins")]

hiddenimports = [
    "uvicorn.logging",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.lifespan.on",
    "h2.config",
    "h2.connection",
    "h2.events",
    "intercept.api.app",
    "intercept.app",
    "intercept.cli",
    "intercept.scanner.checks",
    "intercept.scanner.engine",
    "intercept.proxy.h2",
    "intercept.store.findings",
    "intercept.tools.fuzzer",
]

a = Analysis(
    [str(SRC / "intercept" / "__main__.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pytest"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="intercept",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "apps" / "desktop" / "build" / "icon.png")
    if (ROOT / "apps" / "desktop" / "build" / "icon.png").exists()
    else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="intercept",
)
