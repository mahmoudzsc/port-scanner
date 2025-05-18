# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['scanner_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('settings.json', '.'), ('C:\\path\\to\\python39\\Lib\\site-packages\\PyQt5\\Qt\\plugins', 'PyQt5/Qt/plugins')],
    hiddenimports=['scapy.all', 'reportlab', 'customtkinter', 'tkinter', 'asyncio', 'PyQt5'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=True,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [('v', None, 'OPTION')],
    exclude_binaries=True,
    name='PortScanner',
    debug=True,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['icon.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='PortScanner',
)
