"""AnonVoid - Paket Yöneticisi ve Sandbox Artıkları Temizleme Modülü.

Bu modül; sistemde yüklü olan paket yöneticilerini (APT, Pacman, DNF, Zypper) otomatik
tespit ederek indirme önbelleklerini ve gereksiz paketleri temizler; ayrıca Flatpak
ve Snap sandbox ortamlarının kullanıcı dizininde bıraktığı önbellekleri süpürür.
Root yetkisiyle yeniden oluşturulan dizinlerin sahipliğini (chown) kullanıcıya devreder.
"""

from __future__ import annotations

import glob
import logging
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import sync_disks

logger = logging.getLogger("AnonVoidPkgMgr")


def _fix_ownership(path: str, home_dir: str) -> None:
    """Oluşturulan dosya veya dizin sahipliğini hedef ev dizini sahibine (uid:gid) eşitler."""
    if hasattr(os, "chown") and hasattr(os, "stat"):
        try:
            st = os.stat(home_dir)
            os.chown(path, st.st_uid, st.st_gid)
        except Exception as err:
            logger.debug("Sahiplik düzeltilemedi (%s): %s", path, err)


def detect_package_managers() -> List[str]:
    """Sistemde kurulu ve kullanılabilir paket yöneticilerini tespit eder.

    Returns:
        List[str]: Bulunan paket yöneticilerinin isimleri ('apt', 'pacman', 'dnf', 'zypper').
    """
    found: List[str] = []
    candidates = ["apt-get", "pacman", "dnf", "zypper"]

    for cmd in candidates:
        if shutil.which(cmd) is not None:
            clean_name = "apt" if cmd == "apt-get" else cmd
            found.append(clean_name)

    return found


def clean_package_manager_caches() -> Dict[str, Any]:
    """Tespit edilen paket yöneticilerinin indirme ve paket önbelleklerini temizler.

    Returns:
        Dict[str, Any]: Temizlik sonuçları ve çalıştırılan komutlar.
    """
    managers = detect_package_managers()
    logger.info("Tespit edilen paket yöneticileri: %s", ", ".join(managers) if managers else "Yok")

    results: Dict[str, Any] = {
        "detected_managers": managers,
        "executed_commands": [],
        "errors": [],
    }

    # 1. APT Temizliği (Debian / Ubuntu / Kali)
    if "apt" in managers:
        try:
            cmd1 = ["apt-get", "clean"]
            subprocess.run(cmd1, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30, check=False)
            results["executed_commands"].append("apt-get clean")

            cmd2 = ["apt-get", "autoremove", "-y"]
            subprocess.run(cmd2, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60, check=False)
            results["executed_commands"].append("apt-get autoremove -y")
        except Exception as err:
            results["errors"].append(f"APT temizliği sırasında hata: {err}")

    # 2. Pacman Temizliği (Arch Linux)
    if "pacman" in managers:
        try:
            cmd = ["pacman", "-Scc", "--noconfirm"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60, check=False)
            results["executed_commands"].append("pacman -Scc --noconfirm")
        except Exception as err:
            results["errors"].append(f"Pacman önbellek temizleme hatası: {err}")

    # 3. DNF Temizliği (Fedora / RHEL)
    if "dnf" in managers:
        try:
            cmd = ["dnf", "clean", "all"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=45, check=False)
            results["executed_commands"].append("dnf clean all")
        except Exception as err:
            results["errors"].append(f"DNF temizliği sırasında hata: {err}")

    # 4. Zypper Temizliği (openSUSE)
    if "zypper" in managers:
        try:
            cmd = ["zypper", "clean", "--all"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=45, check=False)
            results["executed_commands"].append("zypper clean --all")
        except Exception as err:
            results["errors"].append(f"Zypper temizliği sırasında hata: {err}")

    sync_disks()
    return results


def clean_sandbox_artifacts(target_home: Optional[str] = None) -> Dict[str, Any]:
    """Flatpak (~/.var/app/) ve Snap (~/snap/) sandbox önbellek dizinlerini temizler.

    Kullanıcı ayarlarını ve verilerini korur; yalnızca geçici 'cache' ve 'Cache' dizinlerini siler.
    Root daemon çalıştığında yeniden açılan dizinlerin sahipliğini (chown) kullanıcıya aktarır.

    Returns:
        Dict[str, Any]: Temizlik istatistikleri.
    """
    home = target_home or os.environ.get("HOME") or os.path.expanduser("~")
    cleared_dirs: List[str] = []
    errors: List[str] = []

    logger.info("Sandbox (Flatpak/Snap) önbellekleri taranıyor: %s", home)

    # 1. Flatpak Önbellekleri: ~/.var/app/<app_id>/cache/*
    flatpak_base = os.path.join(home, ".var", "app")
    if os.path.isdir(flatpak_base):
        for pattern in [os.path.join(flatpak_base, "*", "cache"), os.path.join(flatpak_base, "*", ".cache")]:
            for cache_dir in glob.glob(pattern):
                if os.path.isdir(cache_dir):
                    try:
                        shutil.rmtree(cache_dir, ignore_errors=True)
                        os.makedirs(cache_dir, mode=0o700, exist_ok=True)
                        _fix_ownership(cache_dir, home)
                        cleared_dirs.append(cache_dir)
                    except Exception as err:
                        errors.append(f"Flatpak önbelleği silinemedi ({cache_dir}): {err}")

    # 2. Snap Önbellekleri: ~/snap/<app_name>/common/.cache/*
    snap_base = os.path.join(home, "snap")
    if os.path.isdir(snap_base):
        for pattern in [os.path.join(snap_base, "*", "common", ".cache"), os.path.join(snap_base, "*", "*", ".cache")]:
            for cache_dir in glob.glob(pattern):
                if os.path.isdir(cache_dir):
                    try:
                        shutil.rmtree(cache_dir, ignore_errors=True)
                        os.makedirs(cache_dir, mode=0o700, exist_ok=True)
                        _fix_ownership(cache_dir, home)
                        cleared_dirs.append(cache_dir)
                    except Exception as err:
                        errors.append(f"Snap önbelleği silinemedi ({cache_dir}): {err}")

    sync_disks()
    return {
        "success": len(errors) == 0,
        "cleared_dirs_count": len(cleared_dirs),
        "cleared_dirs": cleared_dirs,
        "errors": errors,
    }
