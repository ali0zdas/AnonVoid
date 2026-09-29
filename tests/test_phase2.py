"""AnonVoid - Faz 2 Adli İz Temizliği Birim ve Entegrasyon Testleri.

Bu dosya; düşük seviyeli C bellek sıfırlama, shred dosya ezme, shell geçmişi yok etme,
log yönetimi, önbellek/MRU temizliği, bellek hijyeni ve ForensicsManager orkestrasyonunu test eder.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.forensics.cache import (
    clean_recently_used_and_mru,
    clean_thumbnail_cache,
    clean_trash_bin,
    get_xdg_paths,
)
from core.forensics.logs import clean_auth_and_session_logs, vacuum_journal_logs
from core.forensics.lowlevel import (
    secure_wipe_bytearray,
    secure_zero_memory,
    shred_file,
    sync_disks,
)
from core.forensics.manager import ForensicsManager
from core.forensics.memory import drop_ram_caches, get_active_swap_devices
from core.forensics.package_mgr import (
    clean_sandbox_artifacts,
    detect_package_managers,
)
from core.forensics.shell import clean_shell_history
from core.forensics.storage import detect_storage_devices, zero_free_space


class TestLowLevelForensics(unittest.TestCase):
    """core/forensics/lowlevel.py testleri."""

    def test_secure_wipe_bytearray(self):
        """Bytearray'in bellekte sıfırlandığını test eder."""
        data = bytearray(b"CokGizliSifre123456!")
        secure_wipe_bytearray(data)
        self.assertEqual(data, bytearray(b"\x00" * 20))

    def test_shred_file_lifecycle(self):
        """Dosyanın üzerine yazılıp, truncate edilip güvenle silindiğini test eder."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"Hassas Adli Veriler - Bash Komutlari" * 100)
            f_path = f.name

        self.assertTrue(os.path.exists(f_path))
        # 2 tur rastgele veri + 1 tur sıfır bayt ile ez ve sil
        success = shred_file(f_path, passes=2, zero_fill=True, remove_after=True)
        self.assertTrue(success)
        self.assertFalse(os.path.exists(f_path))

    def test_shred_non_existent_file(self):
        """Olmayan dosya için shred_file False dönmelidir."""
        self.assertFalse(shred_file("/tmp/non_existent_target_12345.bin"))


class TestShellForensics(unittest.TestCase):
    """core/forensics/shell.py testleri."""

    def test_clean_shell_history_in_temp_home(self):
        """Geçici bir ev dizininde shell geçmişlerinin ezildiğini test eder."""
        with tempfile.TemporaryDirectory() as fake_home:
            # Sahte history dosyaları oluştur
            bash_hist = os.path.join(fake_home, ".bash_history")
            zsh_hist = os.path.join(fake_home, ".zsh_history")
            py_hist = os.path.join(fake_home, ".python_history")

            for path in [bash_hist, zsh_hist, py_hist]:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("sudo rm -rf /gizli\ncurl https://secret.onion\n")

            res = clean_shell_history(target_home=fake_home)
            self.assertTrue(res["success"])
            self.assertEqual(res["cleaned_count"], 3)
            self.assertFalse(os.path.exists(bash_hist))
            self.assertFalse(os.path.exists(zsh_hist))
            self.assertFalse(os.path.exists(py_hist))


class TestCacheForensics(unittest.TestCase):
    """core/forensics/cache.py testleri."""

    def test_clean_thumbnails_and_trash(self):
        """Küçük resimler ve çöp kutusu dosyalarının silindiğini test eder."""
        with tempfile.TemporaryDirectory() as fake_home:
            # Sahte thumbnail dizini
            thumb_normal = os.path.join(fake_home, ".cache", "thumbnails", "normal")
            os.makedirs(thumb_normal, exist_ok=True)
            sample_thumb = os.path.join(thumb_normal, "abc123thumbnail.png")
            with open(sample_thumb, "wb") as f:
                f.write(b"PNG_FAKE_IMAGE_DATA")

            # Sahte trash dizini
            trash_files = os.path.join(fake_home, ".local", "share", "Trash", "files")
            os.makedirs(trash_files, exist_ok=True)
            sample_trash = os.path.join(trash_files, "deleted_document.pdf")
            with open(sample_trash, "wb") as f:
                f.write(b"PDF_SECRET_DATA")

            # Ortam değişkenlerini geçici olarak yönlendir
            old_cache = os.environ.get("XDG_CACHE_HOME")
            old_data = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_CACHE_HOME"] = os.path.join(fake_home, ".cache")
            os.environ["XDG_DATA_HOME"] = os.path.join(fake_home, ".local", "share")

            try:
                t_res = clean_thumbnail_cache(target_home=fake_home)
                self.assertTrue(t_res["success"])
                self.assertFalse(os.path.exists(sample_thumb))

                trash_res = clean_trash_bin(target_home=fake_home)
                self.assertTrue(trash_res["success"])
                self.assertFalse(os.path.exists(sample_trash))
            finally:
                if old_cache is not None:
                    os.environ["XDG_CACHE_HOME"] = old_cache
                else:
                    os.environ.pop("XDG_CACHE_HOME", None)
                if old_data is not None:
                    os.environ["XDG_DATA_HOME"] = old_data
                else:
                    os.environ.pop("XDG_DATA_HOME", None)

    def test_clean_recently_used(self):
        """recently-used.xbel dosyasının temiz boş bir XML iskeletine dönüştürüldüğünü test eder."""
        with tempfile.TemporaryDirectory() as fake_home:
            data_dir = os.path.join(fake_home, ".local", "share")
            os.makedirs(data_dir, exist_ok=True)
            xbel_file = os.path.join(data_dir, "recently-used.xbel")
            with open(xbel_file, "w", encoding="utf-8") as f:
                f.write("<xbel><bookmark href='file:///secret.docx'/></xbel>")

            old_data = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = data_dir
            try:
                res = clean_recently_used_and_mru(target_home=fake_home)
                self.assertTrue(res["success"])
                self.assertTrue(os.path.exists(xbel_file))
                with open(xbel_file, "r", encoding="utf-8") as f:
                    content = f.read()
                self.assertNotIn("secret.docx", content)
                self.assertIn("<?xml", content)
            finally:
                if old_data is not None:
                    os.environ["XDG_DATA_HOME"] = old_data
                else:
                    os.environ.pop("XDG_DATA_HOME", None)


class TestMemoryAndStorageForensics(unittest.TestCase):
    """core/forensics/memory.py ve storage.py testleri."""

    def test_memory_safe_execution(self):
        """drop_ram_caches fonksiyonunun güvenle çalıştığını test eder."""
        res = drop_ram_caches()
        self.assertIsInstance(res, dict)
        self.assertIn("gc_collected_objects", res)

    def test_storage_device_detection(self):
        """detect_storage_devices çağrısının liste döndürdüğünü test eder."""
        devs = detect_storage_devices()
        self.assertIsInstance(devs, list)

    def test_zero_free_space_safe(self):
        """zero_free_space fonksiyonunun 1MB test kotasıyla güvenle çalıştığını test eder."""
        with tempfile.TemporaryDirectory() as tmpdir:
            res = zero_free_space(target_dir=tmpdir, max_fill_mb=1)
            self.assertTrue(res["success"])
            self.assertTrue(res["bytes_written"] > 0)


class TestForensicsManager(unittest.TestCase):
    """core/forensics/manager.py entegrasyon testleri."""

    def test_forensics_manager_full_run(self):
        """ForensicsManager'ın hedefleri koordine ettiğini ve ilerleme bildirdiğini test eder."""
        with tempfile.TemporaryDirectory() as fake_home:
            # Fake shell file
            bash_file = os.path.join(fake_home, ".bash_history")
            with open(bash_file, "w") as f:
                f.write("echo 'merhaba dunya'\n")

            progress_logs = []

            def _on_progress(pct: int, msg: str):
                progress_logs.append((pct, msg))

            manager = ForensicsManager()
            targets = {
                "clean_shell_history": True,
                "clean_thumbnails": True,
                "clean_mru_cache": True,
                "clean_trash": True,
                "clean_journal_logs": False,  # Test ortamında journald mock
                "clean_text_logs": False,
                "clean_package_cache": False,
                "clean_memory_caches": True,
                "clean_swap": False,
                "ssd_trim": False,
                "free_space_zeroing": False,
            }

            report = manager.run_cleanup(
                targets=targets,
                target_home=fake_home,
                progress_callback=_on_progress,
            )

            self.assertTrue(report["completed"])
            self.assertFalse(os.path.exists(bash_file))
            self.assertTrue(len(progress_logs) > 0)
            self.assertEqual(progress_logs[-1][0], 100)  # Son ilerleme %100 olmalı


if __name__ == "__main__":
    unittest.main()
