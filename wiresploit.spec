# -*- mode: python ; coding: utf-8 -*-

import sys
import os
from pathlib import Path

# Get the root directory from current working directory
ROOT = Path(os.getcwd())

# Collect data files
def collect_data_files():
    data_files = []

    # Web files (templates, static assets)
    web_dir = ROOT / 'web'
    if web_dir.exists():
        for f in web_dir.rglob('*'):
            if f.is_file() and not f.name.endswith('.backup'):
                rel = f.relative_to(ROOT)
                data_files.append((str(f), str(rel.parent)))

    # Engine modules
    engine_dir = ROOT / 'engine'
    if engine_dir.exists():
        for f in engine_dir.rglob('*.py'):
            if f.is_file() and not f.name.endswith('.backup'):
                rel = f.relative_to(ROOT)
                data_files.append((str(f), str(rel.parent)))

    # Config files
    for f in ['config.py', 'validation.py', '.env.example']:
        fp = ROOT / f
        if fp.exists():
            data_files.append((str(fp), '.'))

    # Requirements
    for f in ['requirements.txt', 'requirements-optional.txt', 'requirements-dev.txt']:
        fp = ROOT / f
        if fp.exists():
            data_files.append((str(fp), '.'))

    return data_files

# Collect binaries (if any)
def collect_binaries():
    binaries = []
    return binaries

# Collect hidden imports
hidden_imports = [
    'engine',
    'engine.store',
    'engine.engine',
    'engine.tooling',
    'engine.security',
    'engine.credentials',
    'engine.kali_categories',
    'engine.kali_env',
    'engine.native',
    'engine.web_providers',
    'engine.catalog',
    'engine.awesome_catalog',
    'validation',
    'config',
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops.auto',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan.on',
    'fastapi',
    'fastapi.staticfiles',
    'pydantic',
    'pydantic_core',
    'playwright',
    'playwright.async_api',
    'reportlab',
    'reportlab.lib.pagesizes',
    'reportlab.pdfgen',
    'sqlite3',
    'csv',
    'json',
    'html',
    'asyncio',
    'subprocess',
    'platform',
    'pathlib',
    're',
    'os',
    'sys',
    'io',
    'time',
    'dataclasses',
    'enum',
    'typing',
    'collections',
    'hashlib',
    'secrets',
    'base64',
    'cryptography.hazmat.primitives.ciphers.aead',
    'cryptography.hazmat.primitives.kdf.pbkdf2',
    'cryptography.hazmat.primitives.hashes',
]

a = Analysis(
    ['main.py'],
    pathex=[str(ROOT)],
    binaries=collect_binaries(),
    datas=collect_data_files(),
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'test_*',
        'tests',
        'pytest',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'IPython',
        'jupyter',
        'notebook',
        'sphinx',
        'docutils',
        'setuptools',
        'pip',
        'wheel',
        'twine',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='WireSploit',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'web' / 'icon.ico') if (ROOT / 'web' / 'icon.ico').exists() else None,
)