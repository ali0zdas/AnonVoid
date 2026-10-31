"""AnonVoid - Kabuk (Shell) ve REPL Geçmişi Adli Temizlik Modülü.

Bu modül; Bash, Zsh, Fish, Python, GDB, Radare2, MySQL, PostgreSQL ve diğer etkileşimli
kabukların disk üzerinde bıraktığı geçmiş (history) dosyalarını tespit eder, rastgele
verilerle ve sıfır baytlarla ezerek (shred) adli standartlarda yok eder.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, List, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.lowlevel import shred_file

logger = logging.getLogger("AnonVoidShell")


def _fix_ownership(path: str, home_dir: str) -> None:
    """Oluşturulan dosya veya dizin sahipliğini hedef ev dizini sahibine (uid:gid) eşitler."""
    if hasattr(os, "chown") and hasattr(os, "stat"):
        try:
            st = os.stat(home_dir)
            os.chown(path, st.st_uid, st.st_gid)
        except Exception as err:
            logger.debug("Sahiplik düzeltilemedi (%s): %s", path, err)


# Hedef Shell, REPL ve CLI Geçmiş Dosyaları (Kullanıcı Ev Dizinine Göreceli)
SHELL_TARGET_FILES: List[str] = [
    # Kabuklar (Shells)
    ".bash_history",
    ".bash_sessions",
    ".zsh_history",
    ".zhistory",
    ".sh_history",
    ".history",
    ".local/share/fish/fish_history",
    # Yorumlayıcılar ve REPL
    ".python_history",
    ".local/state/python/history",
    ".node_repl_history",
    ".sqlite_history",
    ".mysql_history",
    ".psql_history",
    ".dbshell",
    ".rediscli_history",
    ".mongorc.js",
    # Hata Ayıklayıcılar ve Tersine Mühendislik
    ".gdb_history",
    ".radare2_history",
    # Düzenleyiciler ve Ağ İstemcileri
    ".lesshst",
    ".viminfo",
    ".local/state/nvim/shada/main.shada",
    ".nano_history",
    ".wget-hsts",
]


def clean_shell_history(
    target_home: Optional[str] = None,
    custom_targets: Optional[List[str]] = None,
    shred_passes: int = 1,
) -> Dict[str, Any]:
    """Hedef kullanıcının tüm kabuk ve CLI geçmiş dosyalarını güvenle ezer ve siler.

    Args:
        target_home: Hedef kullanıcının ev dizini yolu (None ise mevcut kullanıcının evi).
        custom_targets: Varsa ek olarak silinecek dosya yolları.
        shred_passes: Dosya üzerine kaç tur rastgele veri yazılacağı.

    Returns:
        Dict[str, Any]: Temizlik sonuç raporu.
    """
    home_dir = target_home or os.environ.get("HOME") or os.path.expanduser("~")
    if not os.path.isdir(home_dir):
        return {
            "success": False,
            "error": f"Kullanıcı ev dizini bulunamadı: {home_dir}",
            "cleaned_files": [],
            "failed_files": [],
            "total_bytes_cleared": 0,
        }

    targets = list(SHELL_TARGET_FILES)
    if custom_targets:
        targets.extend(custom_targets)

    cleaned_files: List[str] = []
    failed_files: List[Dict[str, str]] = []
    total_bytes_cleared = 0

    logger.info("Shell geçmişi temizliği başlatılıyor (Ev Dizini: %s)...", home_dir)

    for rel_path in targets:
        full_path = os.path.join(home_dir, rel_path)
        if not os.path.exists(full_path) and not os.path.islink(full_path):
            continue

        try:
            file_size = 0
            if not os.path.islink(full_path):
                file_size = os.path.getsize(full_path)

            success = shred_file(
                full_path,
                passes=shred_passes,
                zero_fill=True,
                remove_after=True,
            )

            if success:
                cleaned_files.append(full_path)
                total_bytes_cleared += file_size
                logger.info("Shell geçmiş dosyası güvenle ezildi ve silindi: %s", full_path)
            else:
                failed_files.append({"file": full_path, "error": "Ezme işlemi başarısız"})
        except Exception as err:
            logger.warning("Dosya temizlenirken hata oluştu (%s): %s", full_path, err)
            failed_files.append({"file": full_path, "error": str(err)})

    # Çalışan kabuk oturumları için ortam tavsiyesi
    env_recommendations = {
        "HISTFILE": "/dev/null",
        "HISTSIZE": "0",
        "LESSTHISTFILE": "/dev/null",
    }

    return {
        "success": len(failed_files) == 0,
        "cleaned_count": len(cleaned_files),
        "cleaned_files": cleaned_files,
        "failed_files": failed_files,
        "total_bytes_cleared": total_bytes_cleared,
        "environment_recommendations": env_recommendations,
    }
