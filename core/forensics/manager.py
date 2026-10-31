"""AnonVoid - Adli Temizlik Orkestratörü ve Canlı Adli Risk Radarı (Forensics Manager).

Bu modül; shell geçmişi, sistem günlükleri, önbellekler, bellek, depolama, meta veriler
ve paket yöneticisi temizlik modüllerini sıralı ve güvenli bir iş akışı ile koordine eder.
Canlı Adli Risk Radarı (Forensic Exposure Radar) ile hiçbir dosyayı silmeden sistemdeki
adli kalıntı miktarını analiz edip risk skoru (0-100) üretir.
"""

from __future__ import annotations

import glob
import logging
import os
import sys
import time
from typing import Any, Callable, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.cache import (
    clean_browser_caches,
    clean_recently_used_and_mru,
    clean_thumbnail_cache,
    clean_trash_bin,
    get_xdg_paths,
)
from core.forensics.logs import (
    clean_auth_and_session_logs,
    rotate_and_clean_text_logs,
    vacuum_journal_logs,
)
from core.forensics.memory import clean_and_zeroize_swap, drop_ram_caches
from core.forensics.metadata import (
    sanitize_directory_metadata,
    sanitize_file_metadata,
)
from core.forensics.package_mgr import (
    clean_package_manager_caches,
    clean_sandbox_artifacts,
)
from core.forensics.shell import SHELL_TARGET_FILES, clean_shell_history
from core.forensics.storage import run_ssd_trim, zero_free_space

logger = logging.getLogger("AnonVoidForensicsManager")


class ForensicsManager:
    """Tüm adli iz temizleme ve risk tarama modüllerini yöneten merkezi orkestratör."""

    def __init__(self) -> None:
        pass

    def run_cleanup(
        self,
        targets: Dict[str, Any],
        target_home: Optional[str] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> Dict[str, Any]:
        """Kullanıcı tarafından seçilen hedeflere göre adli temizliği yürütür.

        Sıralama Prensibi (Kritik):
          Paket yöneticisi temizliği (apt-get clean vb.) mutlaka sistem günlükleri
          temizliğinden ÖNCE çalışır; böylece paket araçlarının ürettiği taze kurulum
          logları bir sonraki adımda sistem günlükleri temizliğiyle yok edilir.

        Args:
            targets: Temizlenecek hedefleri belirten sözlük.
            target_home: Temizlik yapılacak kullanıcının ev dizini.
            progress_callback: İlerleme bildiren geri çağırma fonksiyonu (yüzde, durum_mesajı).

        Returns:
            Dict[str, Any]: Kapsamlı temizlik sonuç raporu.
        """
        start_time = time.time()
        home = target_home or os.environ.get("HOME") or os.path.expanduser("~")

        logger.info("Adli temizlik orkestrasyonu başlatılıyor (Hedef Ev: %s)...", home)

        def _notify(percent: int, msg: str) -> None:
            if progress_callback:
                try:
                    progress_callback(percent, msg)
                except Exception:
                    pass

        report: Dict[str, Any] = {
            "started_at": start_time,
            "target_home": home,
            "modules": {},
            "errors": [],
            "completed": False,
        }

        # 1. Shell ve Terminal Komut Geçmişi (%15)
        if targets.get("clean_shell_history", True):
            _notify(10, "Shell ve terminal komut geçmişi eziliyor...")
            res = clean_shell_history(target_home=home)
            report["modules"]["shell_history"] = res
            if not res.get("success"):
                report["errors"].extend([f["error"] for f in res.get("failed_files", [])])

        # 2. Masaüstü Önbellekleri, MRU ve Çöp Kutusu (%35)
        if targets.get("clean_thumbnails", True):
            _notify(20, "Küçük resim (thumbnail) önbellekleri temizleniyor...")
            report["modules"]["thumbnails"] = clean_thumbnail_cache(target_home=home)

        if targets.get("clean_mru_cache", True):
            _notify(25, "Son açılan dosyalar (recently-used MRU) sıfırlanıyor...")
            report["modules"]["mru"] = clean_recently_used_and_mru(target_home=home)

        if targets.get("clean_trash", True):
            _notify(30, "Çöp kutusu kalıntıları güvenle siliniyor...")
            report["modules"]["trash"] = clean_trash_bin(target_home=home)

        if targets.get("clean_browser_caches", True):
            _notify(35, "Tarayıcı disk ve derin önbellekleri temizleniyor...")
            deep_clean = targets.get("deep_browser_clean", False)
            report["modules"]["browser_cache"] = clean_browser_caches(
                target_home=home,
                deep_clean=deep_clean,
            )

        # 3. Paket Yöneticisi ve Sandbox Temizliği (%50)
        # KRİTİK: Log temizliğinden önce çalışmalıdır!
        if targets.get("clean_package_cache", True):
            _notify(45, "Paket yöneticisi (APT/Pacman/DNF) önbellekleri süpürülüyor...")
            report["modules"]["package_manager"] = clean_package_manager_caches()
            _notify(50, "Sandbox (Flatpak/Snap) önbellekleri temizleniyor...")
            report["modules"]["sandbox"] = clean_sandbox_artifacts(target_home=home)

        # 4. Sistem Günlükleri ve Oturum Kayıtları (%70)
        if targets.get("clean_journal_logs", True):
            _notify(60, "systemd-journald günlükleri vakumlanıyor...")
            report["modules"]["journal"] = vacuum_journal_logs()

        if targets.get("clean_text_logs", True):
            _notify(68, "Geleneksel metin logları, dpkg/apt kayıtları ve coredump raporları temizleniyor...")
            report["modules"]["text_logs"] = rotate_and_clean_text_logs()
            report["modules"]["auth_logs"] = clean_auth_and_session_logs()

        # 5. RAM ve Takas Alanı (Swap) Hijyeni (%85)
        if targets.get("clean_memory_caches", True):
            _notify(80, "RAM çekirdek önbellekleri serbest bırakılıyor (drop_caches)...")
            report["modules"]["ram_caches"] = drop_ram_caches()

        if targets.get("clean_swap", False):
            _notify(85, "Takas alanı (swap) güvenle sıfırlanıyor...")
            report["modules"]["swap"] = clean_and_zeroize_swap()

        # 6. Depolama Hijyeni (SSD TRIM veya Boş Alan Sıfırlama) (%95)
        if targets.get("ssd_trim", True):
            _notify(90, "SSD TRIM sinyali (fstrim) gönderiliyor...")
            report["modules"]["ssd_trim"] = run_ssd_trim(all_mountpoints=True)

        if targets.get("free_space_zeroing", False):
            _notify(95, "Boş disk alanına sıfır yazılıyor (free-space zeroing)...")
            report["modules"]["free_space_zeroing"] = zero_free_space(target_dir=home)

        # 7. Tamamlandı (%100)
        duration = round(time.time() - start_time, 2)
        report["duration_sec"] = duration
        report["completed"] = True
        _notify(100, f"Adli temizlik başarıyla tamamlandı ({duration}s).")
        logger.info("Adli temizlik tamamlandı (Süre: %0.2fs).", duration)

        return report

    def scan_forensic_exposure(self, target_home: Optional[str] = None) -> Dict[str, Any]:
        """Hedef sistemde hiçbir dosyayı silmeden salt-okunur adli maruziyet taraması yapar.

        Radar Metrikleri:
          - shell_history_lines: Toplam komut geçmişi satır sayısı
          - shell_history_files: Tespit edilen geçmiş dosyası sayısı
          - shell_history_bytes: Toplam geçmiş dosyası boyutu
          - thumbnail_count: Küçük resim önbelleği dosya adedi
          - thumbnail_bytes: Küçük resim önbelleği toplam bayt miktarı
          - browser_cache_bytes: Tarayıcı disk önbelleği boyutu
          - trash_files: Çöp kutusundaki dosya adedi
          - trash_bytes: Çöp kutusundaki dosyaların toplam boyutu
          - system_log_bytes: /var/log altındaki okunabilir log boyutu
          - risk_score: 0-100 arası ağırlıklı adli maruziyet puanı (0 = Tertemiz, 100 = Kritik)
          - risk_level: 'DÜŞÜK', 'ORTA', 'YÜKSEK', 'KRİTİK' risk etiketi

        Args:
            target_home: Taranacak kullanıcının ev dizini yolu.

        Returns:
            Dict[str, Any]: Adli Maruziyet Radar Raporu.
        """
        home = target_home or os.environ.get("HOME") or os.path.expanduser("~")
        logger.info("Canlı Adli Maruziyet Radarı başlatılıyor (Ev Dizini: %s)...", home)

        # 1. Shell ve Terminal Geçmişi Analizi (Salt-okunur)
        shell_history_lines = 0
        shell_history_files = 0
        shell_history_bytes = 0

        for rel in SHELL_TARGET_FILES:
            full_path = os.path.join(home, rel)
            if os.path.isfile(full_path) and not os.path.islink(full_path):
                try:
                    sz = os.path.getsize(full_path)
                    shell_history_files += 1
                    shell_history_bytes += sz
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = sum(1 for _ in f)
                        shell_history_lines += lines
                except Exception as err:
                    logger.debug("Shell geçmişi okunamadı (%s): %s", full_path, err)

        # 2. Küçük Resim (Thumbnail) Analizi (Salt-okunur)
        xdg = get_xdg_paths(home)
        thumb_dir = os.path.join(xdg["cache"], "thumbnails")
        thumbnail_count = 0
        thumbnail_bytes = 0

        if os.path.isdir(thumb_dir):
            for root, _, files in os.walk(thumb_dir):
                for f in files:
                    fp = os.path.join(root, f)
                    if os.path.isfile(fp) and not os.path.islink(fp):
                        try:
                            thumbnail_count += 1
                            thumbnail_bytes += os.path.getsize(fp)
                        except OSError:
                            pass

        # 3. Tarayıcı Disk Önbelleği Analizi (Salt-okunur)
        browser_cache_bytes = 0
        browser_patterns = [
            os.path.join(xdg["cache"], "mozilla", "firefox"),
            os.path.join(xdg["cache"], "google-chrome"),
            os.path.join(xdg["cache"], "chromium"),
            os.path.join(xdg["cache"], "BraveSoftware"),
            os.path.join(xdg["cache"], "microsoft-edge"),
            os.path.join(xdg["cache"], "opera"),
        ]

        for b_dir in browser_patterns:
            if os.path.isdir(b_dir):
                for root, _, files in os.walk(b_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        if os.path.isfile(fp) and not os.path.islink(fp):
                            try:
                                browser_cache_bytes += os.path.getsize(fp)
                            except OSError:
                                pass

        # 4. Çöp Kutusu (Trash) Analizi (Salt-okunur)
        trash_dir = os.path.join(xdg["data"], "Trash", "files")
        trash_files = 0
        trash_bytes = 0

        if os.path.isdir(trash_dir):
            for root, _, files in os.walk(trash_dir):
                for f in files:
                    fp = os.path.join(root, f)
                    if os.path.isfile(fp) and not os.path.islink(fp):
                        try:
                            trash_files += 1
                            trash_bytes += os.path.getsize(fp)
                        except OSError:
                            pass

        # 5. Sistem Günlükleri (/var/log) Analizi (Salt-okunur)
        system_log_bytes = 0
        var_log = "/var/log"
        if os.path.isdir(var_log):
            for root, _, files in os.walk(var_log):
                for f in files:
                    fp = os.path.join(root, f)
                    if os.path.isfile(fp) and not os.path.islink(fp):
                        try:
                            system_log_bytes += os.path.getsize(fp)
                        except (OSError, PermissionError):
                            pass

        # 6. Ağırlıklı Adli Risk Skoru Hesaplama (0 - 100)
        # - Shell Geçmişi: 25 Puan (Komut geçmişi en yüksek adli kanıttır)
        shell_score = 0
        if shell_history_lines > 0:
            shell_score = min(25, 5 + int(shell_history_lines / 20))

        # - Küçük Resimler: 20 Puan (Silinen görsellerin delili)
        thumb_score = 0
        if thumbnail_count > 0:
            thumb_score = min(20, 5 + int(thumbnail_count / 15))

        # - Tarayıcı Önbelleği: 20 Puan (Ziyaret edilen siteler, JS kodları)
        browser_mb = browser_cache_bytes / (1024 * 1024)
        browser_score = min(20, int(browser_mb / 5)) if browser_mb > 0 else 0

        # - Çöp Kutusu: 15 Puan (Silinmiş ama diske açık dosyalar)
        trash_score = 0
        if trash_files > 0:
            trash_score = min(15, 5 + trash_files)

        # - Sistem Logları: 20 Puan (Sistem olayları ve oturumlar)
        log_mb = system_log_bytes / (1024 * 1024)
        log_score = min(20, int(log_mb / 10)) if log_mb > 0 else 0

        total_risk_score = min(100, shell_score + thumb_score + browser_score + trash_score + log_score)

        if total_risk_score <= 25:
            risk_level = "DÜŞÜK"
        elif total_risk_score <= 50:
            risk_level = "ORTA"
        elif total_risk_score <= 75:
            risk_level = "YÜKSEK"
        else:
            risk_level = "KRİTİK"

        radar_report: Dict[str, Any] = {
            "target_home": home,
            "shell_history_lines": shell_history_lines,
            "shell_history_files": shell_history_files,
            "shell_history_bytes": shell_history_bytes,
            "thumbnail_count": thumbnail_count,
            "thumbnail_bytes": thumbnail_bytes,
            "browser_cache_bytes": browser_cache_bytes,
            "trash_files": trash_files,
            "trash_bytes": trash_bytes,
            "system_log_bytes": system_log_bytes,
            "risk_score": total_risk_score,
            "risk_level": risk_level,
            "details": {
                "shell_score": shell_score,
                "thumbnail_score": thumb_score,
                "browser_score": browser_score,
                "trash_score": trash_score,
                "log_score": log_score,
            },
        }

        logger.info(
            "Adli Maruziyet Radarı Tamamlandı: Risk Skoru: %d (%s)",
            total_risk_score,
            risk_level,
        )
        return radar_report
