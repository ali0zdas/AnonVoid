"""AnonVoid - Modern Depolama (SSD/NVMe/HDD) ve Boş Alan Hijyeni Modülü.

Bu modül; sürücü türünü (SSD/NVMe Flash veya Dönen Manyetik HDD) tespit eder,
FTL (Flash Translation Layer) ve Aşınma Dengeleme kısıtlamalarını aşmak için
SSD TRIM (fstrim) komutunu tetikler ve silinmiş dosya bloklarını adli veri kurtarma
(file carving) yöntemlerine karşı boş alan sıfırlama (free-space zeroing) ile doldurur.
"""

from __future__ import annotations

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

logger = logging.getLogger("AnonVoidStorage")


def detect_storage_devices() -> List[Dict[str, Any]]:
    """Sistemdeki blok depolama aygıtlarını ve türlerini (/sys/block) tespit eder.

    rotational değeri:
      - 0: Katı Hal Sürücüsü (SSD / NVMe / eMMC Flash)
      - 1: Dönen Manyetik Disk (HDD)

    Returns:
        List[Dict[str, Any]]: Bulunan disklerin listesi.
    """
    devices: List[Dict[str, Any]] = []
    sys_block = "/sys/block"

    if not os.path.exists(sys_block):
        return devices

    try:
        for entry in os.listdir(sys_block):
            # Sanal (loop, ram, dm-) aygıtları filtrele
            if entry.startswith(("loop", "ram", "dm-", "sr", "zram")):
                continue

            rot_path = os.path.join(sys_block, entry, "queue", "rotational")
            size_path = os.path.join(sys_block, entry, "size")

            is_rotational = True
            if os.path.exists(rot_path):
                try:
                    with open(rot_path, "r", encoding="utf-8") as f:
                        val = f.read().strip()
                        is_rotational = (val == "1")
                except OSError:
                    pass

            size_sectors = 0
            if os.path.exists(size_path):
                try:
                    with open(size_path, "r", encoding="utf-8") as f:
                        size_sectors = int(f.read().strip())
                except (OSError, ValueError):
                    pass

            size_gb = round((size_sectors * 512) / (1024**3), 2)
            disk_type = "HDD (Manyetik)" if is_rotational else "SSD/NVMe (Flash)"

            devices.append({
                "device": entry,
                "is_ssd": not is_rotational,
                "disk_type": disk_type,
                "size_gb": size_gb,
            })
    except Exception as err:
        logger.warning("Depolama aygıtları taranırken hata: %s", err)

    return devices


def run_ssd_trim(all_mountpoints: bool = True) -> Dict[str, Any]:
    """Bağlı tüm dosya sistemlerine fstrim göndererek FTL'nin silinen blokları serbest bırakmasını sağlar.

    SSD ve NVMe sürücülerde işletim sistemi tarafından silinen dosyaların
    flash hücrelerinden kalıcı olarak temizlenebilmesi için TRIM sinyali zorunludur.

    Args:
        all_mountpoints: True ise 'fstrim -av', False ise 'fstrim -v /'.

    Returns:
        Dict[str, Any]: TRIM komutu sonuç raporu.
    """
    logger.info("SSD TRIM (fstrim) işlemi başlatılıyor...")
    result: Dict[str, Any] = {
        "success": False,
        "trimmed_output": "",
        "error": None,
    }

    cmd = ["fstrim", "-av"] if all_mountpoints else ["fstrim", "-v", "/"]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )

        if proc.returncode == 0:
            result["success"] = True
            result["trimmed_output"] = proc.stdout.strip()
            logger.info("SSD TRIM başarıyla tamamlandı: %s", result["trimmed_output"])
        else:
            result["error"] = proc.stderr.strip() or f"fstrim çıkış kodu: {proc.returncode}"
            logger.warning("fstrim uyarısı/hatası: %s", result["error"])
    except FileNotFoundError:
        result["error"] = "fstrim komutu sistemde bulunamadı (util-linux paketi gerekebilir)."
    except subprocess.TimeoutExpired:
        result["error"] = "fstrim zaman aşımına uğradı (120 saniye)."
    except Exception as err:
        result["error"] = f"TRIM çalıştırılırken beklenmeyen hata: {err}"

    return result


def zero_free_space(
    target_dir: str = "/",
    block_size_kb: int = 1024,
    reserve_mb: int = 200,
    max_fill_mb: Optional[int] = None,
) -> Dict[str, Any]:
    """Hedef disk bölümündeki silinmiş artık blokları (unallocated space) sıfır yazarak temizler.

    Dosya sisteminde silinmiş dosya parçalarının (forensic carving) kurtarılmasını
    engellemek için geçici bir sıfır dosyası (.fp_zero_space.tmp) açılır,
    belirlenen güvenlik payı (reserve_mb) kalana kadar disk sıfırla doldurulup silinir.

    Args:
        target_dir: Boş alanı sıfırlanacak dizin veya bağlama noktası.
        block_size_kb: Her yazma turunda yazılacak blok boyutu (Kilobayt).
        reserve_mb: Sistemin kilitlenmesini önlemek için boş bırakılacak rezerv alan (Megabayt).
        max_fill_mb: Maksimum yazılacak alan sınırı (Megabayt) (None ise diski doldurana kadar).

    Returns:
        Dict[str, Any]: İşlem özeti ve yazılan bayt miktarı.
    """
    logger.info("Boş alan sıfırlama (free-space zeroing) başlatılıyor: %s", target_dir)
    result: Dict[str, Any] = {
        "success": False,
        "bytes_written": 0,
        "error": None,
    }

    if not os.path.exists(target_dir):
        result["error"] = f"Hedef dizin bulunamadı: {target_dir}"
        return result

    # Güvenlik payı ve maksimum dolum kontrolleri
    reserve_bytes = reserve_mb * 1024 * 1024
    max_fill_bytes = (max_fill_mb * 1024 * 1024) if max_fill_mb is not None else None
    temp_file = os.path.join(target_dir, f".fp_zero_space_{os.getpid()}.tmp")

    zero_chunk = b"\x00" * (block_size_kb * 1024)
    total_written = 0

    try:
        with open(temp_file, "wb") as f:
            while True:
                # Maksimum sınır kontrolü
                if max_fill_bytes is not None and total_written >= max_fill_bytes:
                    break

                # Kalan boş disk alanını kontrol et
                usage = shutil.disk_usage(target_dir)
                if usage.free <= reserve_bytes:
                    logger.info("Güvenlik rezerv sınırına (%d MB) ulaşıldı; doldurma tamamlandı.", reserve_mb)
                    break

                available_space = usage.free - reserve_bytes
                if max_fill_bytes is not None:
                    available_space = min(available_space, max_fill_bytes - total_written)

                to_write = min(len(zero_chunk), available_space)
                if to_write <= 0:
                    break

                f.write(zero_chunk[:to_write])
                total_written += to_write

            f.flush()
            os.fsync(f.fileno())

        result["success"] = True
        result["bytes_written"] = total_written
        logger.info(
            "Boş alana toplam %0.2f MB sıfır yazıldı.",
            total_written / (1024 * 1024),
        )
    except (OSError, IOError) as err:
        # Disk dolduğunda ENOSPC (No space left on device) normal karşılanır
        result["success"] = True
        result["bytes_written"] = total_written
        logger.info("Disk son sınırına kadar dolduruldu: %s", err)
    except Exception as err:
        result["error"] = f"Boş alan sıfırlanırken hata oluştu: {err}"
    finally:
        # Geçici dosyayı kesinlikle kaldır ve diskleri senkronize et
        if os.path.exists(temp_file):
            try:
                os.unlink(temp_file)
            except OSError:
                pass
        sync_disks()

    return result
