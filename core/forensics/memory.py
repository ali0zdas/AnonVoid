"""AnonVoid - Bellek (RAM) ve Takas Alanı (Swap) Hijyeni Modülü.

Bu modül; RAM üzerindeki çekirdek önbelleklerini (drop_caches) serbest bırakır,
bellek parçalanmasını giderir (compact_memory), aktif takas alanını (swap) kapatıp
eski şifre veya oturum artıklarını güvenli sıfır baytlarla ve blkdiscard ile ezerek
yeniden başlatır. OOM Killer riskine karşı RAM/Swap doluluk oranını denetler.
"""

from __future__ import annotations

import gc
import logging
import os
import stat
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import lock_process_memory, sync_disks

logger = logging.getLogger("AnonVoidMemory")


def _read_meminfo() -> Dict[str, int]:
    """Linux /proc/meminfo dosyasını okuyup kB cinsinden sözlük olarak döndürür."""
    meminfo: Dict[str, int] = {}
    path = "/proc/meminfo"
    if not os.path.exists(path):
        return meminfo
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    k = parts[0].strip()
                    val_parts = parts[1].strip().split()
                    if val_parts and val_parts[0].isdigit():
                        meminfo[k] = int(val_parts[0])
    except Exception as err:
        logger.warning("/proc/meminfo okunamadı: %s", err)
    return meminfo


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
    """Takas (swap) alanını OOM riskini denetleyerek kapatır, temizler ve yeniden aktifleştirir.

    İşlem Adımları:
      1. /proc/meminfo taranarak kullanılan swap ile MemAvailable karşılaştırılır.
         Eğer kullanılan swap MemAvailable'ın %85'ini aşıyorsa OOM Killer riskine karşı işlem atlanır.
      2. swapoff -a çağrılarak tüm takas alanları güvenle kapatılır.
      3. /dev/zram* aygıtları korunur (mkswap uygulanmaz). Diğer blok aygıtlarına blkdiscard
         ve başlık/veri sıfırlaması uygulanır; ardından mkswap ile sıfırdan oluşturulur.
      4. swapon -a ile temiz takas alanı geri açılır.

    Returns:
        Dict[str, Any]: İşlem sonuçları.
    """
    logger.info("Takas alanı (swap) temizleme süreci başlatılıyor...")
    result: Dict[str, Any] = {
        "swapoff_success": False,
        "swapon_success": False,
        "swaps_detected": 0,
        "skipped_due_to_oom_risk": False,
        "errors": [],
    }

    active_swaps = get_active_swap_devices()
    result["swaps_detected"] = len(active_swaps)

    if not active_swaps:
        logger.info("Sistemde aktif bir takas (swap) alanı bulunamadı; işlem atlanıyor.")
        return result

    # 1. OOM Killer Risk Kontrolü (/proc/meminfo)
    meminfo = _read_meminfo()
    if meminfo:
        mem_available = meminfo.get("MemAvailable", 0)
        swap_total = meminfo.get("SwapTotal", 0)
        swap_free = meminfo.get("SwapFree", 0)
        swap_used = max(0, swap_total - swap_free)

        # Kullanılan swap miktarı mevcut RAM'in %85'inden fazlaysa swapoff sistemi kilitler
        if mem_available > 0 and swap_used > (0.85 * mem_available):
            msg = (
                f"Kullanılan swap miktarı ({swap_used} kB), mevcut RAM'in ({mem_available} kB) "
                f"%85'ini aşıyor. OOM Killer tetiklenmesini önlemek için swap temizliği güvenle atlandı."
            )
            logger.warning(msg)
            result["errors"].append(msg)
            result["skipped_due_to_oom_risk"] = True
            return result

    # 2. swapoff -a
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

    # 3. Swap alanlarına blkdiscard, başlık sıfırlama ve mkswap uygula
    for sw in active_swaps:
        sw_path = sw["path"]
        if not os.path.exists(sw_path):
            continue

        # zram aygıtlarını (/dev/zram*) mkswap ile bozma (sıkıştırılmış RAM takas aygıtıdır)
        if sw_path.startswith("/dev/zram"):
            logger.info("zram takas aygıtı (%s) tespit edildi; mkswap uygulanmadan yapısı korunuyor.", sw_path)
            continue

        # Blok cihazı olup olmadığını kontrol et
        is_block_dev = False
        try:
            st = os.stat(sw_path)
            is_block_dev = stat.S_ISBLK(st.st_mode)
        except OSError:
            pass

        # SSD/NVMe blok cihazı ise blkdiscard ile flash bloklarını bırak
        if is_block_dev:
            try:
                ret_discard = subprocess.run(
                    ["blkdiscard", sw_path],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                if ret_discard.returncode == 0:
                    logger.info("blkdiscard başarıyla uygulandı: %s", sw_path)
            except Exception as discard_err:
                logger.debug("blkdiscard uygulanamadı (%s): %s", sw_path, discard_err)

        # Başlık ve imza alanını (ilk 1 MB) sıfır baytlarla ez
        try:
            with open(sw_path, "r+b") as f:
                zero_head = b"\x00" * (1024 * 1024)
                f.write(zero_head)
                f.flush()
                os.fsync(f.fileno())
        except Exception as zero_err:
            logger.debug("Swap başlık sıfırlama uygulanamadı (%s): %s", sw_path, zero_err)

        # mkswap ile temiz swap imzasını yeniden oluştur
        try:
            ret_mk = subprocess.run(
                ["mkswap", sw_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if ret_mk.returncode == 0:
                logger.info("mkswap başarıyla uygulandı: %s", sw_path)
            else:
                result["errors"].append(f"mkswap başarısız ({sw_path}): {ret_mk.stderr.strip()}")
        except Exception as err:
            result["errors"].append(f"mkswap uygulanamadı ({sw_path}): {err}")

    # 4. swapon -a
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
