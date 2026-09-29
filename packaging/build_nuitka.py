#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnonVoid — Nuitka C++ Binary Derleme Boru Hattı
Python kod tabanını doğrudan bağımsız (standalone/onefile) yerel ELF C++ ikili dosyasına derler.
"""

import sys
import os
import shutil
import subprocess
import argparse
from pathlib import Path

# Bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Konsol çıktı kodlaması güvenliği (Windows cp1254 / UTF-8)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def check_nuitka_installed() -> bool:
    """Nuitka derleyicisinin sistemde mevcut olup olmadığını denetler."""
    try:
        res = subprocess.run(
            [sys.executable, "-m", "nuitka", "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def build_nuitka_command(
    main_script: Path,
    output_dir: Path,
    onefile: bool = True,
    lto: bool = True,
    show_progress: bool = True,
) -> list[str]:
    """
    Nuitka derleme komut parametrelerini yapılandırır.
    """
    cmd = [
        sys.executable,
        "-m",
        "nuitka",
        "--standalone",
        f"--output-dir={output_dir.as_posix()}",
        "--output-filename=anonvoid",
        "--enable-plugin=pyqt6",
        "--include-package=core",
        "--include-package=gui",
        "--assume-yes-for-downloads",
        "--remove-output",
    ]

    if onefile:
        cmd.append("--onefile")

    if lto:
        cmd.append("--lto=yes")

    if show_progress:
        cmd.append("--show-progress")
        cmd.append("--show-scons")

    # Giriş dosyası
    cmd.append(main_script.as_posix())
    return cmd


def run_build(
    onefile: bool = True,
    dry_run: bool = False,
    output_dir: str = "dist",
) -> int:
    """
    Derleme sürecini başlatır ve yönetir.
    """
    project_root = Path(__file__).resolve().parent.parent
    main_script = project_root / "main.py"
    dist_path = project_root / output_dir

    print("====================================================================")
    print("  🛡️  ANONVOID — NUITKA C++ DERLEME BORU HATTI")
    print("====================================================================")
    print(f"[*] Proje Kök Dizini : {project_root}")
    print(f"[*] Ana Giriş Noktası : {main_script}")
    print(f"[*] Çıktı Dizini      : {dist_path}")
    print(f"[*] Mod               : {'Tek Dosya (Onefile)' if onefile else 'Bağımsız Dizin (Standalone)'}")

    if not main_script.is_file():
        print(f"[HATA] Ana betik bulunamadı: {main_script}")
        return 1

    cmd = build_nuitka_command(main_script, dist_path, onefile=onefile)

    cmd_str = " ".join(cmd)
    print("\n[+] Yapılandırılan Derleme Komutu:")
    print(f"    {cmd_str}\n")

    if dry_run:
        print("[BİLGİ] --dry-run modu devrede. Derleme fiilen başlatılmadı.")
        return 0

    if not check_nuitka_installed():
        print("[HATA] Nuitka derleyicisi sistemde bulunamadı!")
        print("Lütfen şu komutla Nuitka ve C derleyici gereksinimlerini kurun:")
        print("    pip install nuitka zstandard")
        print("    Debian/Ubuntu için: sudo apt install build-essential ccache patchelf")
        print("    Arch Linux için   : sudo pacman -S base-devel ccache patchelf")
        print("    Fedora için       : sudo dnf install gcc gcc-c++ ccache patchelf")
        return 1

    dist_path.mkdir(parents=True, exist_ok=True)

    print("[*] Derleme işlemi başlatılıyor... (Bu işlem birkaç dakika sürebilir)")
    try:
        res = subprocess.run(cmd, cwd=project_root)
        if res.returncode == 0:
            print("\n====================================================================")
            print("  🎉  NUITKA DERLEMESİ BAŞARIYLA TAMAMLANDI!")
            print("====================================================================")
            print(f"[+] Çıktı dosyası: {dist_path / 'anonvoid'}")
            return 0
        else:
            print(f"\n[HATA] Derleme başarısız oldu (Hata Kodu: {res.returncode})")
            return res.returncode
    except KeyboardInterrupt:
        print("\n[UYARI] Derleme kullanıcı tarafından iptal edildi.")
        return 130
    except Exception as e:
        print(f"\n[HATA] Derleme sırasında beklenmedik hata oluştu: {e}")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description="AnonVoid Nuitka C++ Bağımsız Binary Derleyici"
    )
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Tek dosya yerine bağımsız bir klasör olarak derle",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Komutu fiilen çalıştırmadan yalnızca ekrana yazdırır",
    )
    parser.add_argument(
        "--output-dir",
        default="dist",
        help="Derleme çıktısının kaydedileceği dizin (Varsayılan: dist)",
    )

    args = parser.parse_args()
    sys.exit(
        run_build(
            onefile=not args.standalone,
            dry_run=args.dry_run,
            output_dir=args.output_dir,
        )
    )


if __name__ == "__main__":
    main()
