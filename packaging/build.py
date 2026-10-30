# packaging/build.py
"""Build the Windows app: dist/SecureVault/SecureVault.exe and dist/SecureVault-Windows.zip.

    pip install -r requirements.txt pyinstaller
    python packaging/build.py
"""
import os
import sys
import shutil
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DIST = os.path.join(ROOT, "dist")
BUILD = os.path.join(ROOT, "build")
ICON = os.path.join(HERE, "securevault.ico")
sys.path.insert(0, ROOT)

from main import APP_NAME, APP_VERSION  # noqa: E402

# Qt modules SecureVault never uses; leaving them out keeps the download small
EXCLUDES = [
    "tkinter", "PyQt6.QtWebEngineCore", "PyQt6.QtWebEngineWidgets", "PyQt6.QtQml", "PyQt6.QtQuick",
    "PyQt6.QtMultimedia", "PyQt6.QtPdf", "PyQt6.QtBluetooth", "PyQt6.QtSql", "PyQt6.Qt3DCore",
    "PyQt6.QtOpenGL", "PyQt6.QtDesigner", "PyQt6.QtTest", "PyQt6.QtPositioning", "PyQt6.QtSensors",
]


def make_icon():
    """Render the shield logo to a multi-size .ico (only if it is missing)."""
    if os.path.exists(ICON):
        return
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtGui import QGuiApplication
    from gui.widgets import make_app_icon
    app = QGuiApplication.instance() or QGuiApplication([])
    make_app_icon().pixmap(256, 256).save(ICON, "ICO")
    del app


def version_file():
    parts = (APP_VERSION.split(".") + ["0", "0", "0"])[:4]
    nums = ", ".join(parts)
    path = os.path.join(BUILD, "version_info.txt")
    os.makedirs(BUILD, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({nums}), prodvers=({nums})),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', 'Kiran Gautham'),
      StringStruct('FileDescription', '{APP_NAME} - Ransomware Detection & Prevention'),
      StringStruct('FileVersion', '{APP_VERSION}'),
      StringStruct('ProductName', '{APP_NAME}'),
      StringStruct('ProductVersion', '{APP_VERSION}'),
      StringStruct('OriginalFilename', '{APP_NAME}.exe')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""")
    return path


def main():
    make_icon()
    sep = os.pathsep
    args = [
        sys.executable, "-m", "PyInstaller", os.path.join(HERE, "launcher.py"),
        "--name", APP_NAME,
        "--windowed",
        "--noconfirm",
        "--clean",
        "--icon", ICON,
        "--version-file", version_file(),
        "--paths", ROOT,
        "--distpath", DIST,
        "--workpath", BUILD,
        "--specpath", BUILD,
        "--add-data", f"{os.path.join(ROOT, 'web')}{sep}web",
        "--add-data", f"{os.path.join(ROOT, 'signatures')}{sep}signatures",
        "--hidden-import", "watchdog.observers.read_directory_changes",
    ]
    for module in EXCLUDES:
        args += ["--exclude-module", module]
    subprocess.run(args, check=True, cwd=ROOT)

    archive = shutil.make_archive(os.path.join(DIST, f"{APP_NAME}-Windows"), "zip", DIST, APP_NAME)
    size = os.path.getsize(archive) / 1024 / 1024
    print(f"\nBuilt {os.path.join(DIST, APP_NAME, APP_NAME + '.exe')}")
    print(f"Packaged {archive} ({size:.1f} MB)")


if __name__ == "__main__":
    main()
