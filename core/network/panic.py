"""AnonVoid - Acil Durum Panik Butonu (Emergency Nuke / Kill-Switch) Modülü.

Bu modül; acil bir durumda tek bir çağrıyla tüm ağ trafiğini anında keser (drop),
açık soketleri zorla kapatır, aktif Tor/DNSCrypt kurallarını dondurur,
bellek ve komut geçmişi kalıntılarını hızla ezerek sistemi güvenli bir duruma sokar.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import sync_disks
from core.forensics.memory import drop_ram_caches
from core.forensics.shell import clean_shell_history

logger = logging.getLogger("AnonVoidPanic")

PANIC_TABLE_NAME = "anonvoid-panic"
LEGACY_PANIC_TABLE_NAME = "fp-panic"


def apply_emergency_network_kill() -> bool:
    """Tüm giden ve gelen ağ trafiğini iptables/nftables seviyesinde anında bloke eder."""
    logger.critical("ACİL DURUM AĞ KİLİDİ (KILL-SWITCH) UYGULANIYOR!")
    success = False

    # 1. nftables acil durum drop tablosu
    try:
        panic_nft = (
            f"table inet {PANIC_TABLE_NAME} {{\n"
            "    chain input { type filter hook input priority -1000; policy drop; }\n"
            "    chain output { type filter hook output priority -1000; policy drop; }\n"
            "}\n"
        )
        proc = subprocess.run(["nft", "-f", "-"], input=panic_nft, text=True, timeout=5, check=False)
        if proc.returncode == 0:
            success = True
            logger.info("nftables panik tablosu başarıyla yüklendi; tüm trafik kesildi.")
    except Exception:
        pass

    # 2. iptables fallback: Tüm zincirleri DROP yap
    try:
        subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], timeout=5, check=False)
        subprocess.run(["iptables", "-P", "INPUT", "DROP"], timeout=5, check=False)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "DROP"], timeout=5, check=False)
        subprocess.run(["ip6tables", "-P", "INPUT", "DROP"], timeout=5, check=False)
        success = True
        logger.info("iptables panik kuralları uygulandı.")
    except Exception as err:
        logger.error("iptables panik kuralları uygulanamadı: %s", err)

    # 3. Açık soketleri zorla kes (ss -K)
    try:
        subprocess.run(["ss", "-K"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
    except Exception:
        pass

    return success


def remove_emergency_network_kill() -> bool:
    """Acil durum ağ kilidini kaldırır ve bağlantıyı serbest bırakır."""
    logger.info("Acil durum ağ kilidi kaldırılıyor...")
    for tbl in (PANIC_TABLE_NAME, LEGACY_PANIC_TABLE_NAME):
        try:
            subprocess.run(["nft", "delete", "table", "inet", tbl], timeout=5, check=False)
        except Exception:
            pass

    try:
        subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], timeout=5, check=False)
        subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], timeout=5, check=False)
        subprocess.run(["ip6tables", "-P", "OUTPUT", "ACCEPT"], timeout=5, check=False)
        subprocess.run(["ip6tables", "-P", "INPUT", "ACCEPT"], timeout=5, check=False)
    except Exception:
        pass

    return True


def execute_panic_nuke(
    target_home: Optional[str] = None,
    wipe_shell: bool = True,
    clear_ram: bool = True,
    shutdown_system: bool = False,
) -> Dict[str, Any]:
    """Acil durum panik eylemini yürütür: Ağı keser, belleği ve geçmişi temizler.

    Args:
        target_home: Temizlenecek ev dizini.
        wipe_shell: Shell geçmişi ezilsin mi.
        clear_ram: RAM önbellekleri boşaltılsın mı.
        shutdown_system: İşlem sonrası sistem kapatılsın mı (poweroff).

    Returns:
        Dict[str, Any]: Panik operasyonu sonuç raporu.
    """
    logger.critical("PANİK / NUKE OPERASYONU BAŞLATILDI!")
    start_time = time.time()

    report: Dict[str, Any] = {
        "nuked": True,
        "network_killed": False,
        "shell_wiped": False,
        "ram_cleared": False,
        "system_shutdown_triggered": shutdown_system,
        "timestamp": start_time,
    }

    # 1. Ağı anında kes
    report["network_killed"] = apply_emergency_network_kill()

    # 2. Hızlıca shell geçmişini ez
    if wipe_shell:
        try:
            res = clean_shell_history(target_home=target_home, shred_passes=1)
            report["shell_wiped"] = res.get("success", False)
            logger.info("Panik: Shell geçmişi ezildi.")
        except Exception as err:
            logger.error("Panik: Shell geçmişi ezilemedi: %s", err)

    # 3. RAM önbelleklerini temizle ve senkronize et
    if clear_ram:
        try:
            drop_ram_caches()
            sync_disks()
            report["ram_cleared"] = True
            logger.info("Panik: RAM önbellekleri boşaltıldı.")
        except Exception as err:
            logger.error("Panik: RAM temizlenemedi: %s", err)

    # 4. İsteğe bağlı anında sistemi kapat
    if shutdown_system:
        logger.critical("Panik: Sistem anında kapatılıyor (poweroff)!")
        try:
            subprocess.run(["systemctl", "poweroff", "-i"], timeout=5, check=False)
        except Exception:
            try:
                subprocess.run(["poweroff", "-f"], timeout=5, check=False)
            except Exception:
                pass

    return report
