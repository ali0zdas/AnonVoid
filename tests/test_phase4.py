"""AnonVoid - Faz 4 Modern GUI (PyQt6) Birim Testleri.

Bu dosya; tema stil sayfalarını, StatusRingWidget durum halkasını, servis kartlarını,
adli temizlik matrisini ve ayarlar paneli kontrollerini test eder.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Headless / offscreen Qt ortamı ayarla (Görsel sunucu olmadan test yapabilmek için)
os.environ["QT_QPA_PLATFORM"] = "offscreen"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

GUI_DIR = os.path.join(PROJECT_ROOT, "gui")

from PyQt6.QtWidgets import QApplication

from core.daemon_client import DaemonClient
from gui.forensics_panel import ForensicsPanel
from gui.leak_panel import LeakPanel
from gui.main_window import MainWindow
from gui.settings_panel import SettingsPanel
from gui.themes import (
    THEME_PALETTES,
    contrast_ratio,
    get_available_themes,
    get_theme_stylesheet,
    palette_contrast_report,
)
from gui.widgets import (
    GLYPH_TOR,
    LogConsoleWidget,
    MetricTile,
    NetSpeedBar,
    PageHeader,
    ServiceCardWidget,
    StatusPill,
    StatusRingWidget,
    build_app_icon,
)

# Tema sözleşmesi: her palet bu belirteçleri taşımak zorundadır.
REQUIRED_TOKENS = {
    "name", "bg_main", "bg_sidebar", "bg_surface", "bg_surface_alt", "bg_hover",
    "border", "border_strong", "accent", "accent_hover", "on_accent",
    "text_primary", "text_secondary", "text_muted", "success", "warning",
    "danger", "info", "ring_active", "ring_track", "shadow",
}

# Testler için paylaşımlı QApplication
app = QApplication.instance()
if app is None:
    app = QApplication(["--platform", "offscreen"])


class TestThemes(unittest.TestCase):
    """gui/themes.py testleri."""

    def test_all_five_themes_exist(self):
        """5 dinamik temanın tanımlı olduğunu ve belirteç kümesinin eksiksiz olduğunu doğrular."""
        expected_themes = ["oled", "circuit", "light", "binary", "pixel"]
        for t in expected_themes:
            self.assertIn(t, THEME_PALETTES)
            missing = REQUIRED_TOKENS - set(THEME_PALETTES[t])
            self.assertFalse(missing, f"{t} temasında eksik belirteçler: {sorted(missing)}")

    def test_palette_token_consistency(self):
        """Tüm temalar aynı belirteç kümesini taşımalıdır."""
        expected = set(THEME_PALETTES["oled"])
        for t, pal in THEME_PALETTES.items():
            self.assertEqual(set(pal), expected, f"{t} teması belirteç kümesi farklı")

    def test_ring_active_matches_success(self):
        """Durum halkasının aktif rengi paletin başarı rengiyle aynı olmalıdır."""
        for t, pal in THEME_PALETTES.items():
            self.assertEqual(pal["ring_active"], pal["success"], t)

    def test_all_themes_meet_wcag_aa(self):
        """Metin belirteçleri kendi yüzeylerinde WCAG AA (4.5:1) kontrastı sağlamalıdır."""
        for t in THEME_PALETTES:
            report = palette_contrast_report(t)
            for pair, ratio in report.items():
                self.assertGreaterEqual(
                    ratio, 4.5, f"{t} temasında {pair} kontrastı {ratio:.2f} (AA gerekir: 4.5)"
                )

    def test_contrast_ratio_helper(self):
        """Kontrast yardımcı fonksiyonu bilinen değerleri doğru hesaplar."""
        self.assertAlmostEqual(contrast_ratio("#ffffff", "#000000"), 21.0, places=2)
        self.assertAlmostEqual(contrast_ratio("#000000", "#000000"), 1.0, places=2)

    def test_stylesheet_generation(self):
        """QSS stil sayfasının geçerli metin ürettiğini test eder."""
        for t in THEME_PALETTES:
            qss = get_theme_stylesheet(t)
            self.assertIsInstance(qss, str)
            self.assertIn("QMainWindow", qss)
            self.assertIn("QPushButton#panicButton", qss)

    def test_stylesheet_has_no_hardcoded_legacy_colors(self):
        """Stil sayfası, kaldırılan neon palet renklerini taşımamalıdır."""
        for t in THEME_PALETTES:
            qss = get_theme_stylesheet(t)
            for legacy in ("#00ff88", "#00d4ff", "#ff3366", "#ffaa00"):
                self.assertNotIn(legacy, qss, f"{t} temasında eski renk {legacy} kalmış")

    def test_available_themes_mapping(self):
        """Tema listesi paletlerle eşleşmelidir."""
        available = get_available_themes()
        self.assertEqual(set(available), set(THEME_PALETTES))
        for key, name in available.items():
            self.assertEqual(name, THEME_PALETTES[key]["name"])


class TestGlyphCoverage(unittest.TestCase):
    """Arayüzde kullanılan gliflerin platformda mevcut olduğunu doğrular.

    Kali kurulumlarında emoji yazı tipi genellikle bulunmaz ve emoji butonları
    tofu kutusu olarak çizilir. Bu test, arayüz metinlerindeki her karakterin
    DejaVu Sans'ta karşılığı bulunduğunu doğrulayarak bu regresyonu engeller.
    """

    # Emoji sunumlu karakterler: Tamamlayıcı düzlemlerdeki emoji proper bloğu
    # ve varyasyon seçici 16 (U+FE0F) ile birleşen semboller.
    EMOJI_RANGES = ((0x1F000, 0x1FAFF), (0x1FC00, 0x1FFFD))
    EMOJI_SINGLE = {
        0x2B50, 0x2B55, 0x2934, 0x2935, 0x3030, 0x303D, 0x3297, 0x3299, 0xFE0F,
    }

    @staticmethod
    def _dejavu_cmap():
        try:
            from fontTools.ttLib import TTFont
        except ImportError:
            return None
        import glob

        candidates = glob.glob("/usr/share/fonts/**/DejaVuSans.ttf", recursive=True)
        if not candidates:
            return None
        return set(TTFont(candidates[0]).getBestCmap())

    def _is_emoji(self, ch: str) -> bool:
        cp = ord(ch)
        if cp in self.EMOJI_SINGLE:
            return True
        return any(lo <= cp <= hi for lo, hi in self.EMOJI_RANGES)

    def test_no_emoji_in_gui_sources(self):
        """Arayüz kaynaklarında emoji/pictograph karakter bulunmamalıdır.

        Dingbats bloğundaki ✓ ve ✕ gibi monokrom simgeler tasarımda bilinçli
        olarak kullanılır; bunlar yazı tipinde mevcut olduğu için (ikinci test)
        istisna tutulmaz.
        """
        offenders = []
        for source in sorted(Path(GUI_DIR).glob("*.py")):
            for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
                for ch in set(line):
                    if ord(ch) > 127 and self._is_emoji(ch):
                        offenders.append(f"{source.name}:{line_no} U+{ord(ch):04X}")
        self.assertFalse(offenders, f"Arayüzde emoji tespit edildi: {offenders}")

    def test_all_glyphs_exist_in_dejavu_sans(self):
        """Arayüz metinlerindeki her karakter DejaVu Sans'ta bulunmalıdır."""
        cmap = self._dejavu_cmap()
        if cmap is None:
            self.skipTest("DejaVu Sans veya fontTools bulunamadı")

        missing = []
        for source in sorted(Path(GUI_DIR).glob("*.py")):
            for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
                for ch in set(line):
                    if ord(ch) > 127 and ord(ch) not in cmap:
                        missing.append(f"{source.name}:{line_no} U+{ord(ch):04X}")
        self.assertFalse(missing, f"Yazı tipinde karşılığı olmayan glif: {missing}")


class TestWidgets(unittest.TestCase):
    """gui/widgets.py testleri."""

    def test_status_ring_widget_states(self):
        """StatusRingWidget durumlarının güncellendiğini test eder."""
        ring = StatusRingWidget()
        for st in ["OFFLINE", "CONNECTING", "CONNECTED", "PANIC", "UNAVAILABLE"]:
            ring.set_status(st)
            self.assertEqual(ring._status, st)

    def test_status_ring_turkish_status_text(self):
        """Her durum için Türkçe başlık ve açıklama tanımlı olmalıdır."""
        ring = StatusRingWidget()
        for st in ["OFFLINE", "CONNECTING", "CONNECTED", "PANIC", "UNAVAILABLE"]:
            ring.set_status(st)
            token, title, subtitle, _sweep, _anim = ring._state_style()
            self.assertTrue(title.strip(), f"{st} durumunda başlık boş")
            self.assertTrue(subtitle.strip(), f"{st} durumunda açıklama boş")
            self.assertIn(token, THEME_PALETTES["oled"])

    def test_service_card_widget(self):
        """ServiceCardWidget rozet durumunu test eder."""
        card = ServiceCardWidget("Tor Ağı", "TransPort yönlendirme", GLYPH_TOR)
        card.set_active(True, "TransPort 9040")
        self.assertEqual(card.badge.text(), "TransPort 9040")

        card.set_active(False)
        self.assertEqual(card.badge.text(), "Pasif")

    def test_service_card_badge_follows_theme(self):
        """Rozet rengi tema değişiminde güncellenmelidir."""
        from gui.themes import set_active_theme

        card = ServiceCardWidget("Tor Ağı", "TransPort yönlendirme", GLYPH_TOR)
        card.set_state("Aktif", "success")
        set_active_theme("oled")
        dark_style = card.badge.styleSheet()
        set_active_theme("light")
        light_style = card.badge.styleSheet()
        set_active_theme("oled")
        self.assertNotEqual(dark_style, light_style, "Tema değişince rozet rengi güncellenmedi")

    def test_net_speed_bar(self):
        """NetSpeedBar bilgi güncellemesini test eder."""
        bar = NetSpeedBar()
        bar.update_info("104.244.42.1", True)
        self.assertIn("KORUMALI", bar.ip_label.text())

    def test_net_speed_bar_shows_ip_verbatim(self):
        """Durum şeridi verilen IP metnini olduğu gibi göstermelidir."""
        bar = NetSpeedBar()
        bar.update_info("Tor devresi kuruldu", True, "Sızıntı testi önerilir")
        self.assertIn("Tor devresi kuruldu", bar.ip_label.text())
        self.assertEqual(bar.detail_label.text(), "Sızıntı testi önerilir")

    def test_log_console_widget(self):
        """LogConsoleWidget satır ekleme fonksiyonunu test eder."""
        console = LogConsoleWidget()
        console.append_log("Test adli iz logu", "INFO")
        content = console.toPlainText()
        self.assertIn("Test adli iz logu", content)

    def test_metric_tile_updates(self):
        """MetricTile değer ve renk belirteci güncellemesini test eder."""
        tile = MetricTile("TOR", "Bilinmiyor")
        self.assertEqual(tile.value_widget.text(), "Bilinmiyor")
        tile.set_value("Aktif", "success")
        self.assertEqual(tile.value_widget.text(), "Aktif")

    def test_status_pill_updates(self):
        """StatusPill metin ve belirteç güncellemesini test eder."""
        pill = StatusPill("Bilinmiyor")
        pill.set_state("Daemon bağlı", "success")
        self.assertEqual(pill._label.text(), "Daemon bağlı")

    def test_page_header(self):
        """PageHeader başlık, alt metin ve eylem alanı yönetir."""
        header = PageHeader("Gösterge Paneli", "Alt açıklama")
        self.assertEqual(header.title_label.text(), "Gösterge Paneli")
        header.set_title("Yeni")
        self.assertEqual(header.title_label.text(), "Yeni")

    def test_app_icon_is_not_null(self):
        """Uygulama ikonu QtSvg olmadan da üretilebilmelidir."""
        icon = build_app_icon(64)
        self.assertFalse(icon.isNull())


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

    def _make_window(self):
        client = DaemonClient("/tmp/test.sock")
        return MainWindow(client)

    def test_main_window_pages_and_navigation(self):
        """Ana pencerenin ve sekme geçişlerinin çalıştığını test eder."""
        win = self._make_window()

        self.assertEqual(win.stacked_widget.count(), 4)
        self.assertEqual(win.stacked_widget.currentIndex(), 0)

        # Sayfa değiştir
        win._switch_page(1, win.btn_nav_forensics)
        self.assertEqual(win.stacked_widget.currentIndex(), 1)

        win._switch_page(2, win.btn_nav_leak)
        self.assertEqual(win.stacked_widget.currentIndex(), 2)

    def test_app_bar_tracks_current_page(self):
        """Üst çubuk, etkin sayfanın başlığını göstermelidir."""
        win = self._make_window()
        win._switch_page(1, win.btn_nav_forensics)
        self.assertEqual(win.app_bar_title.text(), "Adli Temizlik")
        win._switch_page(2, win.btn_nav_leak)
        self.assertEqual(win.app_bar_title.text(), "Sızıntı Testi")

    def test_nav_active_flag_is_exclusive(self):
        """Aynı anda yalnızca bir gezinme öğesi etkin olmalıdır."""
        win = self._make_window()
        win._switch_page(2, win.btn_nav_leak)
        actives = [b for b in win._nav_buttons if b.property("active") == "true"]
        self.assertEqual(len(actives), 1)
        self.assertIs(actives[0], win.btn_nav_leak)

    def test_daemon_offline_disables_actions_and_warns(self):
        """Daemon erişilemediğinde eylemler devre dışı kalmalı ve uyarı gösterilmeli.

        Gizlilik aracında "korunduğunu sanmak" en tehlikeli hatadır; bu yüzden
        arayüz korunmadığını açıkça bildirmek zorundadır.
        """
        win = self._make_window()
        win._set_daemon_state(False, "soket bulunamadı")

        self.assertFalse(win._daemon_online)
        self.assertFalse(win.btn_connect.isEnabled())
        self.assertFalse(win.btn_new_circuit.isEnabled())
        self.assertEqual(win.status_ring._status, "UNAVAILABLE")
        self.assertFalse(win.banner.isHidden())
        self.assertIn("daemon", win.banner.text_label.text().lower())

    def test_daemon_online_clears_warning(self):
        """Daemon yeniden erişilebilir olduğunda uyarı kalkmalıdır."""
        win = self._make_window()
        win._set_daemon_state(False, "soket yok")
        win._set_daemon_state(True)
        self.assertTrue(win._daemon_online)
        self.assertTrue(win.banner.isHidden())
        self.assertTrue(win.btn_connect.isEnabled())

    def test_toggle_connection_noop_when_daemon_offline(self):
        """Daemon yokken kalkan açma girişimi sessizce yok sayılmalıdır."""
        win = self._make_window()
        win._set_daemon_state(False, "soket yok")
        before = win._is_connected
        win._toggle_connection()
        self.assertEqual(win._is_connected, before)

    def test_panic_requires_double_confirmation(self):
        """Panik eylemi ilk tıklamada yalnızca hazırlanmalı, ikinci tıklamada onay istemeli."""
        win = self._make_window()

        win._trigger_panic()
        self.assertTrue(win._panic_armed)
        self.assertFalse(win.panic_hint.isHidden())

        # Geri sayım sonunda hazırlık kendiliğinden sıfırlanmalı
        win._disarm_panic()
        self.assertFalse(win._panic_armed)
        self.assertTrue(win.panic_hint.isHidden())

    def test_metrics_are_written_from_daemon_payload(self):
        """Ölçüm kutuları yalnızca daemon'ın bildirdiği gerçek alanlardan doldurulmalıdır."""
        import time as _time

        win = self._make_window()
        stamp = _time.time() - 120
        win._update_metrics(
            {
                "tor_active": True,
                "dnscrypt_active": False,
                "last_circuit_renewal": stamp,
                "uptime_sec": 3671,
                "last_forensics_cleanup": 0.0,
            }
        )
        self.assertEqual(win.tile_tor.value_widget.text(), "Aktif")
        self.assertEqual(win.tile_dns.value_widget.text(), "Pasif")
        self.assertIn("sa", win.tile_uptime.value_widget.text())
        self.assertIn(_time.strftime("%H:%M:%S", _time.localtime(stamp)), win.tile_renewal.value_widget.text())

    def test_apply_theme_switches_active_palette(self):
        """Tema değişimi etkin paleti güncellemelidir."""
        from gui.themes import current_palette, set_active_theme

        win = self._make_window()
        try:
            win.apply_theme("light")
            self.assertEqual(win._current_theme, "light")
            self.assertEqual(current_palette()["accent"], THEME_PALETTES["light"]["accent"])
        finally:
            set_active_theme("oled")


class TestLauncher(unittest.TestCase):
    """`anonvoid` terminal komutunun üretildiği çalıştırıcı betiğini doğrular."""

    TEMPLATE = os.path.join(PROJECT_ROOT, "packaging", "launcher", "anonvoid")
    INSTALLER = os.path.join(PROJECT_ROOT, "packaging", "launcher", "install-user.sh")

    def _read(self, path: str) -> str:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_launcher_template_exists(self):
        self.assertTrue(os.path.isfile(self.TEMPLATE), "Çalıştırıcı şablonu bulunamadı")
        self.assertTrue(os.path.isfile(self.INSTALLER), "Kullanıcı kurulum betiği bulunamadı")

    def test_template_shebang_and_permissions(self):
        self.assertTrue(self._read(self.TEMPLATE).startswith("#!/bin/sh"))
        self.assertTrue(os.access(self.TEMPLATE, os.X_OK), "Çalıştırıcı şablonu çalıştırılabilir olmalı")
        self.assertTrue(os.access(self.INSTALLER, os.X_OK), "Kurulum betiği çalıştırılabilir olmalı")

    def test_template_uses_prefix_placeholder(self):
        """Şablon @PREFIX@ içermeli; kurulumda gerçek dizinle değiştirilir."""
        self.assertIn("@PREFIX@", self._read(self.TEMPLATE))

    def test_template_refuses_root_gui(self):
        """AGENTS.md kuralı: GUI asla root çalıştırılamaz."""
        body = self._read(self.TEMPLATE)
        self.assertIn("id -u", body)
        self.assertIn("GUI root olarak başlatılamaz", body)
        # Root GUI reddi --service hariç tüm modlarda geçerli olmalı
        self.assertIn("NEEDS_GUI", body)

    def test_template_requires_root_for_service(self):
        """--service root yetkisi olmanda reddedilmeli."""
        body = self._read(self.TEMPLATE)
        self.assertIn("--service", body)
        self.assertIn("root yetkisiyle çalıştırılmalıdır", body)

    def test_template_disables_bytecode(self):
        """AGENTS.md kuralı: .pyc üretimi engellenmeli."""
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", self._read(self.TEMPLATE))

    def test_install_sh_uses_shared_template(self):
        """install.sh kendi gömülü kopyasını değil, ortak şablonu kullanmalı."""
        body = self._read(os.path.join(PROJECT_ROOT, "install.sh"))
        self.assertIn("packaging/launcher/anonvoid", body)
        self.assertIn("@PREFIX@", body)

    def test_installed_launcher_has_no_placeholder(self):
        """Kurulmuş çalıştırıcıda çözülmemiş yer tutucusu kalmamalı."""
        installed = os.path.join(
            os.environ.get("XDG_BIN_HOME") or os.path.expanduser("~/.local/bin"), "anonvoid"
        )
        if not os.path.isfile(installed):
            self.skipTest("Kullanıcı düzeyi çalıştırıcı kurulu değil")
        self.assertNotIn("@PREFIX@", self._read(installed))


if __name__ == "__main__":
    unittest.main()
