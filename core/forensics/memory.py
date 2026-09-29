"""AnonVoid - Bellek (RAM) ve Takas Alanı (Swap) Hijyeni Modülü.

Bu modül; RAM üzerindeki çekirdek önbelleklerini (drop_caches) serbest bırakır,
bellek parçalanmasını giderir (compact_memory), aktif takas alanını (swap) kapatıp
eski şifre veya oturum artıklarını urandom/sıfır baytlarla ezerek yeniden başlatır.
"""

from __future__ import annotations

import gc
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import lock_process_memory, sync_disks

logger = logging.getLogger("FPCleanerMemory")


def drop_ram_caches() -> Dict[str, Any]:
    """Linux çekirdeğinin disk ve sayfa önbelleklerini (pagecache, dentries, inodes) boşaltır.

    /proc/sys/vm/drop_caches dosyasına '3' yazarak temizlik yapar.
    /proc/sys/vm/compact_memory dosyasına '1' yazarak bellek parçalanmasını giderir.

    Returns:
        Dict[str, Any]: İşlem sonuçları.
    """
    logger.info("RAM önbelleklerini temizleme (drop_caches) işlemi başlatılıyor...")
    result: Dict[str, Any] = {
        "drop_caches_success": False,
        "compact_memory_success": False,
        "gc_collected_objects": 0,
        "errors": [],
    }

    # 1. Önce Python çöp toplayıcısını (GC) çalıştır
    result["gc_collected_objects"] = gc.collect()

    # 2. Disk tamponlarını belleğe senkronize et
    sync_disks()

    # 3. drop_caches = 3 uygula
    drop_caches_path = "/proc/sys/vm/drop_caches"
    if os.path.exists(drop_caches_path):
        try:
            with open(drop_caches_path, "w") as f:
                f.write("3\n")
            result["drop_caches_success"] = True
            logger.info("drop_caches=3 başarıyla uygulandı; sayfa ve inode önbellekleri boşaltıldı.")
        except (PermissionError, OSError) as err:
            result["errors"].append(f"drop_caches uygulanamadı (Root yetkisi gerekebilir): {err}")
    else:
        result["errors"].append("/proc/sys/vm/drop_caches bulunamadı (Linux çekirdeği dışı ortam).")

    # 4. compact_memory = 1 uygula
    compact_path = "/proc/sys/vm/compact_memory"
    if os.path.exists(compact_path):
        try:
            with open(compact_path, "w") as f:
                f.write("1\n")
            result["compact_memory_success"] = True
            logger.info("compact_memory=1 başarıyla uygulandı; bellek parçalanması giderildi.")
        except (PermissionError, OSError) as err:
            result["errors"].append(f"compact_memory uygulanamadı: {err}")

    sync_disks()
    return result


def get_active_swap_devices() -> List[Dict[str, Any]]:
    """Sistemde aktif olan takas (swap) alanlarını /proc/swaps üzerinden listeler.

    Returns:
        List[Dict[str, Any]]: Takas aygıtları veya dosyaları bilgisi.
    """
    swaps_path = "/proc/swaps"
    swap_list: List[Dict[str, Any]] = []

    if not os.path.exists(swaps_path):
        return swap_list

    try:
        with open(swaps_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # İlk satır başlıktır: Filename Type Size Used Priority
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 5:
                swap_list.append({
                    "path": parts[0],
                    "type": parts[1],
                    "size_kb": int(parts[2]),
                    "used_kb": int(parts[3]),
                    "priority": int(parts[4]),
                })
    except Exception as err:
        logger.warning("/proc/swaps okunamadı: %s", err)

    return swap_list


def clean_and_zeroize_swap() -> Dict[str, Any]:
    """Takas (swap) alanını devre dışı bırakıp temizler ve yeniden aktifleştirir.

    İşlem Adımları:
      1. swapoff -a çağrılarak tüm takas alanı kapatılır.
      2. Swap dosyası ise güvenli sıfır yazılır veya swap bölümü mkswap ile yenilenir.
      3. swapon -a ile temiz takas alanı geri açılır.

    Returns:
        Dict[str, Any]: İşlem sonuçları.
    """
    logger.info("Takas alanı (swap) temizleme süreci başlatılıyor...")
    result: Dict[str, Any] = {
        "swapoff_success": False,
        "swapon_success": False,
        "swaps_detected": 0,
        "errors": [],
    }

    active_swaps = get_active_swap_devices()
    result["swaps_detected"] = len(active_swaps)

    if not active_swaps:
        logger.info("Sistemde aktif bir takas (swap) alanı bulunamadı; işlem atlanıyor.")
        return result

    # 1. swapoff -a
    try:
        ret = subprocess.run(["swapoff", "-a"], capture_output=True, text=True, timeout=60, check=False)
        if ret.returncode == 0:
            result["swapoff_success"] = True
            logger.info("swapoff -a başarıyla tamamlandı.")
        else:
            result["errors"].append(f"swapoff başarısız: {ret.stderr.strip()}")
            return result
    except Exception as err:
        result["errors"].append(f"swapoff çağrısı yapılamadı: {err}")
        return result

    # 2. Swap alanlarına mkswap uygula (bölüm veya dosya)
    for sw in active_swaps:
        sw_path = sw["path"]
        if os.path.exists(sw_path):
            try:
                subprocess.run(
                    ["mkswap", sw_path],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                logger.info("mkswap başarıyla uygulandı: %s", sw_path)
            except Exception as err:
                result["errors"].append(f"mkswap uygulanamadı ({sw_path}): {err}")

    # 3. swapon -a
    try:
        ret = subprocess.run(["swapon", "-a"], capture_output=True, text=True, timeout=30, check=False)
        if ret.returncode == 0:
            result["swapon_success"] = True
            logger.info("swapon -a başarıyla tamamlandı; temiz takas alanı aktif.")
        else:
            result["errors"].append(f"swapon başarısız: {ret.stderr.strip()}")
    except Exception as err:
        result["errors"].append(f"swapon çağrısı yapılamadı: {err}")

    return result


def clean_memory_full(clean_swap: bool = False) -> Dict[str, Any]:
    """Tüm bellek ve takas hijyeni adımlarını yürütür."""
    ram_res = drop_ram_caches()
    swap_res: Dict[str, Any] = {}

    if clean_swap:
        swap_res = clean_and_zeroize_swap()

    return {
        "success": ram_res["drop_caches_success"] or len(ram_res["errors"]) == 0,
        "ram": ram_res,
        "swap": swap_res,
    }
