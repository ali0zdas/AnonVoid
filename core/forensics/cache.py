"""AnonVoid - Önbellek, Küçük Resim ve MRU Artefaktı Temizleme Modülü.

Bu modül; XDG Base Directory standardına uygun olarak masaüstü ortamlarının
(GNOME, KDE Plasma, XFCE vb.) ve uygulamaların diske bıraktığı küçük resim (thumbnails),
en son kullanılan dosyalar (recently-used.xbel), çöp kutusu (Trash) ve tarayıcı disk ile
derin depolama (IndexedDB, Service Worker/CacheStorage) artefaktlarını temizler.
Root daemon çalıştığında kullanıcı ev dizinindeki dosya izinlerini (chown) korur.
"""

from __future__ import annotations

import glob
import logging
import os
import shutil
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import shred_file, sync_disks

logger = logging.getLogger("AnonVoidCache")


def _fix_ownership(path: str, home_dir: str) -> None:
    """Oluşturulan dosya veya dizin sahipliğini hedef ev dizini sahibine (uid:gid) eşitler."""
    if hasattr(os, "chown") and hasattr(os, "stat"):
        try:
            st = os.stat(home_dir)
            os.chown(path, st.st_uid, st.st_gid)
        except Exception as err:
            logger.debug("Sahiplik düzeltilemedi (%s): %s", path, err)


def get_xdg_paths(target_home: Optional[str] = None) -> Dict[str, str]:
    """Hedef kullanıcının XDG standart dizin yollarını tespit eder."""
    home = target_home or os.environ.get("HOME") or os.path.expanduser("~")
    return {
        "home": home,
        "cache": os.environ.get("XDG_CACHE_HOME") or os.path.join(home, ".cache"),
        "data": os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share"),
        "state": os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state"),
    }


def clean_thumbnail_cache(target_home: Optional[str] = None) -> Dict[str, Any]:
    """Küçük resim (thumbnail) önbellek dizinlerini güvenle temizler.

    Küçük resimler, silinmiş hassas resim veya belgelerin bile önizleme
    kopyalarını adli analistlere sunar. Bu dizinler tamamen temizlenir.

    Returns:
        Dict[str, Any]: Temizlik istatistikleri.
    """
    xdg = get_xdg_paths(target_home)
    thumb_base = os.path.join(xdg["cache"], "thumbnails")
    subdirs = ["normal", "large", "x-large", "xx-large", "fail"]

    cleared_count = 0
    total_bytes = 0
    errors: List[str] = []

    logger.info("Küçük resim (thumbnail) önbelleği temizleniyor: %s", thumb_base)

    if not os.path.exists(thumb_base):
        return {"success": True, "cleared_count": 0, "total_bytes": 0, "errors": []}

    for sub in subdirs:
        dir_path = os.path.join(thumb_base, sub)
        if not os.path.isdir(dir_path):
            continue

        try:
            for fname in os.listdir(dir_path):
                fpath = os.path.join(dir_path, fname)
                if os.path.islink(fpath):
                    os.unlink(fpath)
                    continue

                if os.path.isfile(fpath):
                    try:
                        sz = os.path.getsize(fpath)
                        if shred_file(fpath, passes=1, zero_fill=True, remove_after=True):
                            cleared_count += 1
                            total_bytes += sz
                    except OSError as err:
                        errors.append(f"{fpath} silinemedi: {err}")
        except Exception as err:
            errors.append(f"{dir_path} dizini okunamadı: {err}")

    sync_disks()
    return {
        "success": len(errors) == 0,
        "cleared_count": cleared_count,
        "total_bytes": total_bytes,
        "errors": errors,
    }


def clean_recently_used_and_mru(target_home: Optional[str] = None) -> Dict[str, Any]:
    """En son kullanılan dosyalar listesini (MRU) ve XML kayıtlarını sıfırlar.

    Dosya yeniden oluşturulduğunda kök (root) sahipliği yerine ev dizini
    sahibinin (st_uid, st_gid) atanmasını zorunlu kılar.

    Hedefler:
      - recently-used.xbel
      - GTK ve dosya yöneticisi son açılanlar listesi

    Returns:
        Dict[str, Any]: Temizlik sonuçları.
    """
    xdg = get_xdg_paths(target_home)
    mru_targets = [
        os.path.join(xdg["data"], "recently-used.xbel"),
        os.path.join(xdg["home"], ".recently-used"),
        os.path.join(xdg["home"], ".recently-used.xbel"),
    ]

    cleared_files: List[str] = []
    errors: List[str] = []

    logger.info("Son kullanılan dosyalar (MRU) kayıtları temizleniyor...")

    for path in mru_targets:
        if not os.path.exists(path) and not os.path.islink(path):
            continue

        try:
            if os.path.islink(path):
                os.unlink(path)
                cleared_files.append(path)
                continue

            # Boş geçerli bir XBEL iskeleti oluştur veya sıfırla
            empty_xbel = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<xbel version="1.0"\n'
                '      xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks"\n'
                '      xmlns:mime="http://www.freedesktop.org/standards/shared-mime-info"\n'
                '></xbel>\n'
            )
            shred_file(path, passes=1, zero_fill=True, remove_after=False)
            with open(path, "w", encoding="utf-8") as f:
                f.write(empty_xbel)

            # Root daemon dosya oluşturduğunda sahipliği kullanıcıya devret
            _fix_ownership(path, xdg["home"])

            cleared_files.append(path)
            logger.info("MRU kaydı başarıyla temizlendi ve izinler korundu: %s", path)
        except Exception as err:
            errors.append(f"{path} temizlenemedi: {err}")

    sync_disks()
    return {
        "success": len(errors) == 0,
        "cleared_files": cleared_files,
        "errors": errors,
    }


def clean_trash_bin(target_home: Optional[str] = None) -> Dict[str, Any]:
    """Masaüstü Çöp Kutusunu (Trash) ve silme bilgilerini (.trashinfo) güvenle temizler.

    Returns:
        Dict[str, Any]: Temizlik istatistikleri.
    """
    xdg = get_xdg_paths(target_home)
    trash_dirs = [
        os.path.join(xdg["data"], "Trash", "files"),
        os.path.join(xdg["data"], "Trash", "info"),
        os.path.join(xdg["data"], "Trash", "expunged"),
    ]

    cleared_items = 0
    total_bytes = 0
    errors: List[str] = []

    logger.info("Çöp kutusu kalıntıları temizleniyor...")

    for t_dir in trash_dirs:
        if not os.path.isdir(t_dir):
            continue

        try:
            for item in os.listdir(t_dir):
                item_path = os.path.join(t_dir, item)
                if os.path.islink(item_path):
                    os.unlink(item_path)
                    cleared_items += 1
                    continue

                if os.path.isfile(item_path):
                    sz = os.path.getsize(item_path)
                    if shred_file(item_path, passes=1, zero_fill=True, remove_after=True):
                        cleared_items += 1
                        total_bytes += sz
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path, ignore_errors=True)
                    cleared_items += 1
        except Exception as err:
            errors.append(f"Çöp kutusu dizini temizlenirken hata: {err}")

    sync_disks()
    return {
        "success": len(errors) == 0,
        "cleared_items": cleared_items,
        "total_bytes": total_bytes,
        "errors": errors,
    }


def clean_browser_caches(
    target_home: Optional[str] = None,
    deep_clean: bool = False,
) -> Dict[str, Any]:
    """Kullanıcı profillerine dokunmadan tarayıcı disk önbelleklerini temizler.

    deep_clean=True seçildiğinde IndexedDB ve Service Worker/CacheStorage derin
    önbellek hedefleri de temizlenir. Parolalar ve yer imleri korunur.

    Returns:
        Dict[str, Any]: Temizlik sonuçları.
    """
    xdg = get_xdg_paths(target_home)
    cache_base = xdg["cache"]

    browser_cache_patterns = [
        os.path.join(cache_base, "mozilla", "firefox"),
        os.path.join(cache_base, "google-chrome"),
        os.path.join(cache_base, "chromium"),
        os.path.join(cache_base, "BraveSoftware"),
        os.path.join(cache_base, "microsoft-edge"),
        os.path.join(cache_base, "opera"),
    ]

    cleared_dirs: List[str] = []
    errors: List[str] = []

    # 1. Standart disk önbellekleri (HTTP cache)
    for b_path in browser_cache_patterns:
        if not os.path.exists(b_path):
            continue

        try:
            shutil.rmtree(b_path, ignore_errors=True)
            cleared_dirs.append(b_path)
            logger.info("Tarayıcı disk önbelleği temizlendi: %s", b_path)
        except Exception as err:
            errors.append(f"{b_path} silinemedi: {err}")

    # 2. Opsiyonel Derin Temizlik: IndexedDB ve Service Worker / CacheStorage
    if deep_clean:
        config_base = os.path.join(xdg["home"], ".config")
        deep_patterns = [
            # Chromium tabanlı tarayıcılar
            os.path.join(config_base, "google-chrome", "*", "IndexedDB"),
            os.path.join(config_base, "google-chrome", "*", "Service Worker", "CacheStorage"),
            os.path.join(config_base, "google-chrome", "*", "Service Worker", "ScriptCache"),
            os.path.join(config_base, "chromium", "*", "IndexedDB"),
            os.path.join(config_base, "chromium", "*", "Service Worker", "CacheStorage"),
            os.path.join(config_base, "chromium", "*", "Service Worker", "ScriptCache"),
            os.path.join(config_base, "BraveSoftware", "Brave-Browser", "*", "IndexedDB"),
            os.path.join(config_base, "BraveSoftware", "Brave-Browser", "*", "Service Worker", "CacheStorage"),
            os.path.join(config_base, "microsoft-edge", "*", "IndexedDB"),
            os.path.join(config_base, "microsoft-edge", "*", "Service Worker", "CacheStorage"),
            os.path.join(config_base, "opera", "IndexedDB"),
            # Firefox yerel depolama
            os.path.join(xdg["home"], ".mozilla", "firefox", "*", "storage", "default"),
            os.path.join(xdg["home"], ".mozilla", "firefox", "*", "serviceworker.txt"),
        ]

        for pat in deep_patterns:
            for d_path in glob.glob(pat):
                if os.path.islink(d_path):
                    try:
                        os.unlink(d_path)
                        cleared_dirs.append(d_path)
                    except OSError:
                        pass
                elif os.path.isdir(d_path):
                    try:
                        shutil.rmtree(d_path, ignore_errors=True)
                        cleared_dirs.append(d_path)
                        logger.info("Tarayıcı derin depolama (IndexedDB/ServiceWorker) temizlendi: %s", d_path)
                    except Exception as err:
                        errors.append(f"{d_path} silinemedi: {err}")
                elif os.path.isfile(d_path):
                    try:
                        shred_file(d_path, passes=1, zero_fill=True, remove_after=True)
                        cleared_dirs.append(d_path)
                    except Exception as err:
                        errors.append(f"{d_path} silinemedi: {err}")

    sync_disks()
    return {
        "success": True,
        "cleared_dirs": cleared_dirs,
        "errors": errors,
    }


def clean_all_cache_artifacts(
    target_home: Optional[str] = None,
    deep_clean: bool = False,
) -> Dict[str, Any]:
    """Tüm önbellek, MRU, küçük resim, çöp kutusu ve tarayıcı temizliklerini çalıştırır."""
    thumb_res = clean_thumbnail_cache(target_home)
    mru_res = clean_recently_used_and_mru(target_home)
    trash_res = clean_trash_bin(target_home)
    browser_res = clean_browser_caches(target_home, deep_clean=deep_clean)

    return {
        "success": thumb_res["success"] and mru_res["success"] and trash_res["success"],
        "thumbnails": thumb_res,
        "mru": mru_res,
        "trash": trash_res,
        "browser_cache": browser_res,
    }
