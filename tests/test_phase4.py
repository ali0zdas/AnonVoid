"""AnonVoid - Faz 4 Modern GUI (PyQt6) Birim Testleri.

Bu dosya; tema stil sayfalarını, StatusRingWidget durum halkasını, servis kartlarını,
adli temizlik matrisini ve ayarlar paneli kontrollerini test eder.
"""

from __future__ import annotations

import os
import sys
import unittest

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Headless / offscreen Qt ortamı ayarla (Görsel sunucu olmadan test yapabilmek için)
os.environ["QT_QPA_PLATFORM"] = "offscreen"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication

from core.daemon_client import DaemonClient
from gui.forensics_panel import ForensicsPanel
from gui.leak_panel import LeakPanel
from gui.main_window import MainWindow
from gui.settings_panel import SettingsPanel
from gui.themes import THEME_PALETTES, get_theme_stylesheet
from gui.widgets import (
    LogConsoleWidget,
    NetSpeedBar,
    ServiceCardWidget,
    StatusRingWidget,
)

# Testler için paylaşımlı QApplication
app = QApplication.instance()
if app is None:
    app = QApplication(["--platform", "offscreen"])


class TestThemes(unittest.TestCase):
    """gui/themes.py testleri."""

    def test_all_five_themes_exist(self):
        """5 dinamik temanın tanımlı olduğunu doğrular."""
        expected_themes = ["oled", "circuit", "light", "binary", "pixel"]
        for t in expected_themes:
            self.assertIn(t, THEME_PALETTES)
            pal = THEME_PALETTES[t]
            self.assertIn("bg_main", pal)
            self.assertIn("accent", pal)
            self.assertIn("danger", pal)
            self.assertIn("ring_active", pal)

    def test_stylesheet_generation(self):
        """QSS stil sayfasının geçerli metin ürettiğini test eder."""
        for t in ["oled", "circuit", "light", "binary", "pixel"]:
            qss = get_theme_stylesheet(t)
            self.assertIsInstance(qss, str)
            self.assertIn("QMainWindow", qss)
            self.assertIn("QPushButton#panicButton", qss)


class TestWidgets(unittest.TestCase):
    """gui/widgets.py testleri."""

    def test_status_ring_widget_states(self):
        """StatusRingWidget durumlarının güncellendiğini test eder."""
        ring = StatusRingWidget()
        for st in ["OFFLINE", "CONNECTING", "CONNECTED", "PANIC"]:
            ring.set_status(st)
            self.assertEqual(ring._status, st)

    def test_service_card_widget(self):
        """ServiceCardWidget rozet durumunu test eder."""
        card = ServiceCardWidget("Tor Ağı", "TransPort yönlendirme", "🧅")
        card.set_active(True, "TransPort 9040")
        self.assertEqual(card.badge.text(), "TransPort 9040")

        card.set_active(False)
        self.assertEqual(card.badge.text(), "Pasif")

    def test_net_speed_bar(self):
        """NetSpeedBar bilgi güncellemesini test eder."""
        bar = NetSpeedBar()
        bar.update_info("104.244.42.1", True)
        self.assertIn("KORUMALI", bar.ip_label.text())

    def test_log_console_widget(self):
        """LogConsoleWidget satır ekleme fonksiyonunu test eder."""
        console = LogConsoleWidget()
        console.append_log("Test adli iz logu", "INFO")
        content = console.toPlainText()
        self.assertIn("Test adli iz logu", content)


class TestForensicsPanel(unittest.TestCase):
    """gui/forensics_panel.py testleri."""

    def test_matrix_targets_and_selection(self):
        """Seçim matrisi ve toplu seçim metodlarını test eder."""
        client = DaemonClient("/tmp/test.sock")
        panel = ForensicsPanel(client)

        targets = panel.get_selected_targets()
        self.assertTrue(targets["clean_shell_history"])
        self.assertTrue(targets["clean_journal_logs"])

        # Seçimi temizle
        panel._clear_selection()
        cleared = panel.get_selected_targets()
        self.assertFalse(cleared["clean_shell_history"])
        self.assertFalse(cleared["clean_journal_logs"])

        # Tümünü seç
        panel._select_all()
        selected_all = panel.get_selected_targets()
        self.assertTrue(selected_all["clean_shell_history"])
        self.assertTrue(selected_all["free_space_zeroing"])


class TestMainWindow(unittest.TestCase):
    """gui/main_window.py testleri."""

    def test_main_window_pages_and_navigation(self):
        """Ana pencerenin ve sekme geçişlerinin çalıştığını test eder."""
        client = DaemonClient("/tmp/test.sock")
        win = MainWindow(client)

        self.assertEqual(win.stacked_widget.count(), 4)
        self.assertEqual(win.stacked_widget.currentIndex(), 0)

        # Sayfa değiştir
        win._switch_page(1, win.btn_nav_forensics)
        self.assertEqual(win.stacked_widget.currentIndex(), 1)

        win._switch_page(2, win.btn_nav_leak)
        self.assertEqual(win.stacked_widget.currentIndex(), 2)


if __name__ == "__main__":
    unittest.main()
