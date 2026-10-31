"""AnonVoid - Faz 2 Adli İz Temizliği Birim ve Entegrasyon Testleri.

Bu dosya; düşük seviyeli C bellek sıfırlama, shred dosya ezme, shell geçmişi yok etme,
log yönetimi, önbellek/MRU temizliği, bellek hijyeni ve ForensicsManager orkestrasyonunu test eder.
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import unittest
import zlib
from unittest import mock

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
    disable_coredumps_and_ptrace,
    secure_wipe_bytearray,
    secure_zero_memory,
    shred_file,
    sync_disks,
)
from core.forensics.metadata import (
    _sanitize_jpeg_bytes,
    _sanitize_png_bytes,
    sanitize_file_metadata,
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
        missing = os.path.join(
            os.environ.get("XDG_RUNTIME_DIR") or os.path.expanduser("~/.cache"),
            "anonvoid-test-var-olmayan-hedef.bin",
        )
        self.assertFalse(shred_file(missing))

    def test_disable_coredumps_and_ptrace(self):
        """disable_coredumps_and_ptrace fonksiyonunun güvenle çalıştığını test eder."""
        try:
            res = disable_coredumps_and_ptrace()
            self.assertIsInstance(res, bool)
        except Exception as err:
            self.fail(f"disable_coredumps_and_ptrace beklenmedik hata fırlattı: {err}")


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

    def test_scan_forensic_exposure_read_only(self):
        """scan_forensic_exposure fonksiyonunun salt-okunur olarak risk skoru ve seviyesi ürettiğini doğrular."""
        with tempfile.TemporaryDirectory() as fake_home:
            # Örnek geçmiş dosyaları ve küçük resimler oluştur
            bash_path = os.path.join(fake_home, ".bash_history")
            with open(bash_path, "w", encoding="utf-8") as f:
                f.write("whoami\nls -la\nssh user@remote.corp\n")

            thumb_dir = os.path.join(fake_home, ".cache", "thumbnails", "normal")
            os.makedirs(thumb_dir, exist_ok=True)
            thumb_file = os.path.join(thumb_dir, "preview123.png")
            with open(thumb_file, "wb") as f:
                f.write(b"SAMPLE_THUMBNAIL_BYTES")

            manager = ForensicsManager()
            report = manager.scan_forensic_exposure(target_home=fake_home)

            self.assertIsInstance(report, dict)
            self.assertIn("risk_score", report)
            self.assertIn("risk_level", report)
            self.assertTrue(0 <= report["risk_score"] <= 100)
            self.assertIn(report["risk_level"], ["DÜŞÜK", "ORTA", "YÜKSEK", "KRİTİK"])
            self.assertEqual(report["shell_history_lines"], 3)
            self.assertEqual(report["thumbnail_count"], 1)

            # Salt-okunur doğrulama: hiçbir dosya silinmemiş veya değiştirilmemiş olmalıdır
            self.assertTrue(os.path.exists(bash_path), "Shell geçmiş dosyası silinmemelidir (salt-okunur tarama)")
            self.assertTrue(os.path.exists(thumb_file), "Thumbnail dosyası silinmemelidir (salt-okunur tarama)")


class TestMetadataSanitizer(unittest.TestCase):
    """core/forensics/metadata.py testleri."""

    def _generate_test_png(self, include_text_chunk: bool = True) -> bytes:
        header = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
        ihdr_chunk = (
            struct.pack(">I", len(ihdr_data))
            + b"IHDR"
            + ihdr_data
            + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data))
        )
        chunks = [ihdr_chunk]

        if include_text_chunk:
            text_data = b"Author\x00AnonVoidForensicTest"
            text_chunk = (
                struct.pack(">I", len(text_data))
                + b"tEXt"
                + text_data
                + struct.pack(">I", zlib.crc32(b"tEXt" + text_data))
            )
            chunks.append(text_chunk)

        idat_data = zlib.compress(b"\x00\x00")
        idat_chunk = (
            struct.pack(">I", len(idat_data))
            + b"IDAT"
            + idat_data
            + struct.pack(">I", zlib.crc32(b"IDAT" + idat_data))
        )
        chunks.append(idat_chunk)

        iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
        chunks.append(iend_chunk)

        return header + b"".join(chunks)

    def _generate_test_jpeg(self) -> bytes:
        soi = b"\xFF\xD8"
        app1_payload = b"Exif\x00\x00AnonVoidCameraTest"
        app1_len = len(app1_payload) + 2
        app1 = b"\xFF\xE1" + struct.pack(">H", app1_len) + app1_payload
        sos = b"\xFF\xDA\x00\x02\x00\xFF\xD9"
        return soi + app1 + sos

    def test_strip_png_metadata_bytes(self):
        """PNG tEXt chunk'larının _sanitize_png_bytes tarafından başarıyla ayıklandığını doğrular."""
        raw_png = self._generate_test_png(include_text_chunk=True)
        self.assertIn(b"tEXt", raw_png)
        self.assertIn(b"AnonVoidForensicTest", raw_png)

        cleaned, count, bytes_removed = _sanitize_png_bytes(raw_png)
        self.assertEqual(count, 1)
        self.assertGreater(bytes_removed, 0)
        self.assertNotIn(b"tEXt", cleaned)
        self.assertNotIn(b"AnonVoidForensicTest", cleaned)
        self.assertTrue(cleaned.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn(b"IHDR", cleaned)
        self.assertIn(b"IEND", cleaned)

    def test_strip_jpeg_metadata_bytes(self):
        """JPEG APP1 (EXIF) segmentlerinin _sanitize_jpeg_bytes tarafından temizlendiğini doğrular."""
        raw_jpeg = self._generate_test_jpeg()
        self.assertIn(b"\xFF\xE1", raw_jpeg)
        self.assertIn(b"AnonVoidCameraTest", raw_jpeg)

        cleaned, count, bytes_removed = _sanitize_jpeg_bytes(raw_jpeg)
        self.assertEqual(count, 1)
        self.assertGreater(bytes_removed, 0)
        self.assertNotIn(b"\xFF\xE1", cleaned)
        self.assertNotIn(b"AnonVoidCameraTest", cleaned)
        self.assertTrue(cleaned.startswith(b"\xFF\xD8"))
        self.assertTrue(cleaned.endswith(b"\xFF\xD9"))

    def test_sanitize_file_metadata_png_file(self):
        """sanitize_file_metadata fonksiyonunun gerçek dosya üzerinde atomik temizlik yaptığını doğrular."""
        with tempfile.TemporaryDirectory() as tmpdir:
            png_file = os.path.join(tmpdir, "test_photo.png")
            with open(png_file, "wb") as f:
                f.write(self._generate_test_png(include_text_chunk=True))

            res = sanitize_file_metadata(png_file)
            self.assertTrue(res["success"])
            self.assertEqual(res["method"], "pure_python_png")
            self.assertEqual(res["tags_or_chunks_removed"], 1)

            with open(png_file, "rb") as f:
                content = f.read()
            self.assertNotIn(b"tEXt", content)
            self.assertNotIn(b"AnonVoidForensicTest", content)


if __name__ == "__main__":
    unittest.main()
