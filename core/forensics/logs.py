"""AnonVoid - Sistem Günlükleri ve Adli Anomali Önleme Modülü.

Bu modül; adli inceleme araçlarında (Autopsy, Plaso, Log2Timeline) "delil karartma
anomalisi" veya "kırmızı bayrak" uyandırmayacak biçimde sistem günlüklerini temizler.
systemd-journald yerleşik vakumlama protokolü, logrotate simülasyonu, oturum kayıtları
(wtmp/btmp/lastlog), çökme/coredump raporları (/var/lib/systemd/coredump) ve paket yöneticisi
kurulum loglarının (/var/log/dpkg.log, /var/log/apt/history.log) güvenli yönetilmesini sağlar.
"""

from __future__ import annotations

import glob
import logging
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import shred_file, sync_disks

logger = logging.getLogger("AnonVoidLogs")

# Oturum ve Giriş İzleme Kayıt Dosyaları
AUTH_LOG_FILES: List[str] = [
    "/var/log/wtmp",
    "/var/log/btmp",
    "/var/log/lastlog",
    "/var/run/utmp",
    "/run/utmp",
]

# Çökme ve Çekirdek Bellek Döküm (Coredump) Dizinleri/Kalıpları
CRASH_LOG_PATTERNS: List[str] = [
    "/var/crash/*",
    "/var/log/apport.log*",
    "/var/log/core/*",
    "/var/lib/systemd/coredump/*",
]

# Paket Yöneticisi Kurulum ve Geçmiş Günlükleri
PACKAGE_LOG_PATTERNS: List[str] = [
    "/var/log/dpkg.log*",
    "/var/log/apt/history.log*",
    "/var/log/apt/term.log*",
    "/var/log/apt/eipp.log*",
]


def vacuum_journal_logs() -> Dict[str, Any]:
    """systemd-journald günlüklerini sistemin kendi protokolüyle arşivden düşürür.

    Log dosyalarını aniden yok etmek yerine systemd'nin standart vakumlama
    mekanizması kullanılarak adli zaman çizelgesi anomalisi engellenir.

    Returns:
        Dict[str, Any]: İşlem sonuçları.
    """
    logger.info("systemd-journald vakumlama süreci başlatılıyor...")
    results: Dict[str, Any] = {
        "rotate_success": False,
        "vacuum_time_success": False,
        "vacuum_size_success": False,
        "errors": [],
    }

    # 1. Aktif journal dosyasını kapatıp arşive taşı (rotate)
    try:
        ret = subprocess.run(
            ["journalctl", "--rotate"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=False,
        )
        results["rotate_success"] = ret.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as err:
        results["errors"].append(f"journalctl rotate başarısız: {err}")

    # 2. 1 saniyeden eski tüm günlükleri vakumla
    try:
        ret = subprocess.run(
            ["journalctl", "--vacuum-time=1s"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        results["vacuum_time_success"] = ret.returncode == 0
        if ret.stdout:
            results["vacuum_time_output"] = ret.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as err:
        results["errors"].append(f"journalctl vacuum-time başarısız: {err}")

    # 3. Boyut sınırını 1M seviyesine çek
    try:
        ret = subprocess.run(
            ["journalctl", "--vacuum-size=1M"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            check=False,
        )
        results["vacuum_size_success"] = ret.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired) as err:
        results["errors"].append(f"journalctl vacuum-size başarısız: {err}")

    return results


def rotate_and_clean_text_logs() -> Dict[str, Any]:
    """Geleneksel /var/log metin günlüklerini logrotate ile döndürür ve arşivleri temizler.

    Ayrıca /var/log/dpkg.log ve /var/log/apt/history.log paket kurulum kayıtlarını güvenle temizler.

    Returns:
        Dict[str, Any]: Temizlik istatistikleri.
    """
    logger.info("/var/log metin günlükleri, paket kayıtları ve arşivleri temizleniyor...")
    cleaned_archives: List[str] = []
    errors: List[str] = []

    # 1. logrotate -f tetikle (varsa)
    logrotate_conf = "/etc/logrotate.conf"
    if os.path.exists(logrotate_conf):
        try:
            subprocess.run(
                ["logrotate", "-f", logrotate_conf],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
            )
        except Exception as err:
            errors.append(f"logrotate çağrısı yapılamadı: {err}")

    # 2. Arşivlenmiş eski loglar ve paket yöneticisi logları (*.gz, *.1, *.old, dpkg.log, apt/history.log)
    archive_patterns = [
        "/var/log/*.gz",
        "/var/log/*.1",
        "/var/log/*.old",
        "/var/log/*/*.gz",
        "/var/log/*/*.1",
    ] + PACKAGE_LOG_PATTERNS

    for pat in archive_patterns:
        for file_path in glob.glob(pat):
            if os.path.islink(file_path):
                try:
                    os.unlink(file_path)
                    cleaned_archives.append(file_path)
                except OSError:
                    pass
                continue

            if os.path.isfile(file_path):
                try:
                    if shred_file(file_path, passes=1, zero_fill=True, remove_after=True):
                        cleaned_archives.append(file_path)
                except Exception as err:
                    errors.append(f"{file_path} silinemedi: {err}")

    sync_disks()

    return {
        "success": True,
        "cleaned_archives_count": len(cleaned_archives),
        "cleaned_archives": cleaned_archives,
        "errors": errors,
    }


def clean_auth_and_session_logs() -> Dict[str, Any]:
    """Giriş, oturum ve coredump kayıtlarını (/var/log/wtmp, btmp, systemd/coredump) temizler.

    Oturum dosyaları tamamen silinirse yetkilendirme servisleri bozulabileceğinden
    dosyalar 0 bayt boyutuna çekilir (truncate) ve izinleri korunur.
    Coredump dosyaları ise güvenle ezilerek silinir.

    Returns:
        Dict[str, Any]: İşlem sonuçları.
    """
    logger.info("Oturum ve kimlik doğrulama kayıtları (wtmp/btmp/lastlog/coredump) temizleniyor...")
    cleared_logs: List[str] = []
    errors: List[str] = []

    # 1. Oturum kütüklerini truncate(0) ile boşalt
    for log_path in AUTH_LOG_FILES:
        if not os.path.exists(log_path):
            continue

        try:
            with open(log_path, "wb") as f:
                f.truncate(0)
            cleared_logs.append(log_path)
            logger.info("Oturum kaydı boşaltıldı: %s", log_path)
        except (PermissionError, OSError) as err:
            errors.append(f"{log_path} boşaltılamadı: {err}")

    # 2. Çökme ve systemd-coredump bellek dökümü raporlarını ezerek sil
    for pat in CRASH_LOG_PATTERNS:
        for fpath in glob.glob(pat):
            if os.path.islink(fpath):
                try:
                    os.unlink(fpath)
                    cleared_logs.append(fpath)
                except OSError:
                    pass
                continue

            if os.path.isfile(fpath):
                try:
                    if shred_file(fpath, passes=1, zero_fill=True, remove_after=True):
                        cleared_logs.append(fpath)
                except Exception as err:
                    errors.append(f"Çökme/coredump raporu silinemedi ({fpath}): {err}")

    sync_disks()

    return {
        "success": len(errors) == 0,
        "cleared_logs": cleared_logs,
        "errors": errors,
    }


def clean_all_logs() -> Dict[str, Any]:
    """Tüm log temizleme mekanizmalarını sıralı biçimde çalıştırır."""
    journal_res = vacuum_journal_logs()
    text_res = rotate_and_clean_text_logs()
    auth_res = clean_auth_and_session_logs()

    return {
        "success": True,
        "journal": journal_res,
        "text_logs": text_res,
        "auth_logs": auth_res,
    }
