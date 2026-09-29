"""AnonVoid - Adli Temizlik Orkestratörü (Forensics Manager).

Bu modül; shell, sistem logları, önbellekler, bellek, depolama ve paket yöneticisi
temizlik modüllerini merkezi bir iş akışı ve ilerleme yüzdesi (progress) ile koordine eder.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Callable, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.cache import (
    clean_browser_caches,
    clean_recently_used_and_mru,
    clean_thumbnail_cache,
    clean_trash_bin,
)
from core.forensics.logs import (
    clean_auth_and_session_logs,
    rotate_and_clean_text_logs,
    vacuum_journal_logs,
)
from core.forensics.memory import clean_and_zeroize_swap, drop_ram_caches
from core.forensics.package_mgr import (
    clean_package_manager_caches,
    clean_sandbox_artifacts,
)
from core.forensics.shell import clean_shell_history
from core.forensics.storage import run_ssd_trim, zero_free_space

logger = logging.getLogger("FPCleanerForensicsManager")


class ForensicsManager:
    """Tüm adli iz temizleme modüllerini yürüten merkezi orkestratör."""

    def __init__(self) -> None:
        pass

    def run_cleanup(
        self,
        targets: Dict[str, Any],
        target_home: Optional[str] = None,
        progress_callback: Optional[Callable[[int, str], None]] = None,
    ) -> Dict[str, Any]:
        """Kullanıcı tarafından seçilen hedeflere göre adli temizliği yürütür.

        Args:
            targets: Temizlenecek hedefleri belirten sözlük (örn: clean_shell_history: True).
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

        # 1. Shell ve Komut Geçmişi (%15)
        if targets.get("clean_shell_history", True):
            _notify(10, "Shell ve terminal komut geçmişi eziliyor...")
            res = clean_shell_history(target_home=home)
            report["modules"]["shell_history"] = res
            if not res.get("success"):
                report["errors"].extend([f["error"] for f in res.get("failed_files", [])])

        # 2. Küçük Resimler ve MRU (%30)
        if targets.get("clean_thumbnails", True):
            _notify(25, "Küçük resim (thumbnail) önbellekleri temizleniyor...")
            report["modules"]["thumbnails"] = clean_thumbnail_cache(target_home=home)

        if targets.get("clean_mru_cache", True):
            _notify(35, "Son açılan dosyalar (recently-used MRU) sıfırlanıyor...")
            report["modules"]["mru"] = clean_recently_used_and_mru(target_home=home)

        if targets.get("clean_trash", True):
            _notify(45, "Çöp kutusu kalıntıları güvenle siliniyor...")
            report["modules"]["trash"] = clean_trash_bin(target_home=home)

        # 3. Sistem Günlükleri (%60)
        if targets.get("clean_journal_logs", True):
            _notify(55, "systemd-journald günlükleri vakumlanıyor...")
            report["modules"]["journal"] = vacuum_journal_logs()

        if targets.get("clean_text_logs", True):
            _notify(65, "Geleneksel metin logları ve oturum kayıtları temizleniyor...")
            report["modules"]["text_logs"] = rotate_and_clean_text_logs()
            report["modules"]["auth_logs"] = clean_auth_and_session_logs()

        # 4. Paket Yöneticisi ve Sandbox (%75)
        if targets.get("clean_package_cache", True):
            _notify(75, "Paket yöneticisi ve sandbox (Flatpak/Snap) önbellekleri süpürülüyor...")
            report["modules"]["package_manager"] = clean_package_manager_caches()
            report["modules"]["sandbox"] = clean_sandbox_artifacts(target_home=home)

        # 5. RAM ve Takas Alanı Hijyeni (%85)
        if targets.get("clean_memory_caches", True):
            _notify(85, "RAM çekirdek önbellekleri serbest bırakılıyor (drop_caches)...")
            report["modules"]["ram_caches"] = drop_ram_caches()

        if targets.get("clean_swap", False):
            _notify(90, "Takas alanı (swap) sıfırlanıyor...")
            report["modules"]["swap"] = clean_and_zeroize_swap()

        # 6. Depolama (SSD TRIM veya Boş Alan Sıfırlama) (%95)
        if targets.get("ssd_trim", True):
            _notify(92, "SSD TRIM sinyali (fstrim) gönderiliyor...")
            report["modules"]["ssd_trim"] = run_ssd_trim(all_mountpoints=True)

        if targets.get("free_space_zeroing", False):
            _notify(95, "Boş disk alanına sıfır yazılıyor (free-space zeroing)...")
            report["modules"]["free_space_zeroing"] = zero_free_space(target_dir=home)

        # Tamamlandı
        duration = round(time.time() - start_time, 2)
        report["duration_sec"] = duration
        report["completed"] = True
        _notify(100, f"Adli temizlik başarıyla tamamlandı ({duration}s).")
        logger.info("Adli temizlik tamamlandı (Süre: %0.2fs).", duration)

        return report
