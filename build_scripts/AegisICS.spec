# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['..\\src\\main.py'],
    pathex=['..\\src'],
    binaries=[('C:\\Python314\\python314.dll', '.')],
    datas=[
        ('..\\src\\templates', 'templates'),
        ('..\\src\\static', 'static'),
        ('..\\src\\model', 'model'),
    ],
    hiddenimports=[
        'flask',
        'sqlalchemy',
        'serial',
        'bleach',
        'sklearn.ensemble',
        'sklearn.tree',
        'serial.tools.list_ports',
        'flask_limiter',
        'reportlab',
        'webview'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='AegisICS_v2.2.2',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
