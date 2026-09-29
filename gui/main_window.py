"""AnonVoid - Ana Kontrol Merkezi ve Gösterge Paneli (Main Window).

Bu modül; sol kenar çubuğu navigasyonunu, dinamik durum halkasını (StatusRingWidget),
servis kartlarını, acil durum panik butonunu, sistem tepsisi (System Tray) entegrasyonunu
ve Wayland root engeli güvenlik denetimini barındıran merkezi kullanıcı arayüzüdür.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True

from PyQt6.QtCore import QSize, Qt, QTimer
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from core.daemon_client import AsyncDaemonWorker, DaemonClient
from gui.forensics_panel import ForensicsPanel
from gui.leak_panel import LeakPanel
from gui.settings_panel import SettingsPanel
from gui.themes import get_theme_stylesheet
from gui.widgets import NetSpeedBar, ServiceCardWidget, StatusRingWidget


class MainWindow(QMainWindow):
    """AnonVoid Ana Masaüstü Arayüzü."""

    def __init__(self, client: Optional[DaemonClient] = None) -> None:
        super().__init__()
        self.client = client or DaemonClient()

        # Root GUI Güvenlik Engeli (AGENTS.md ve Wayland Kuralı)
        if hasattr(os, "getuid") and os.getuid() == 0:
            QMessageBox.critical(
                None,
                "Güvenlik Uyarısı (Privilege Violation)",
                "AnonVoid grafik arayüzü asla root veya sudo ile çalıştırılamaz.\n"
                "Lütfen uygulamayı normal kullanıcı oturumunuzdan başlatın.\n"
                "Sistem düzeyindeki işlemler arka plandaki anonvoid daemon'a iletilecektir.",
            )
            sys.exit(1)

        self.setWindowTitle("AnonVoid — Dijital Ayak İzi ve Ağ Gizliliği")
        self.setMinimumSize(960, 640)
        self.resize(1020, 680)

        # Varsayılan Tema
        self._current_theme = "oled"
        self._is_connected = False

        self._init_ui()
        self._init_tray_icon()
        self.apply_theme(self._current_theme)

        # Periyodik Daemon Durum Zamanlayıcısı (Her 3 saniyede bir)
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_daemon_status)
        self._poll_timer.start(3000)

        # İlk durumu sorgula
        self._poll_daemon_status()

    def _init_ui(self) -> None:
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ---------------------------------------------------------------------
        # 1. Sol Kenar Çubuğu (Sidebar)
        # ---------------------------------------------------------------------
        sidebar = QFrame(self)
        sidebar.setObjectName("sidebarFrame")
        sidebar.setFixedWidth(220)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(14, 20, 14, 16)
        side_layout.setSpacing(8)

        # Logo ve Başlık
        brand_layout = QVBoxLayout()
        brand_layout.setSpacing(2)
        logo_title = QLabel("🛡️ ANONVOID", sidebar)
        logo_title.setStyleSheet("font-size: 16px; font-weight: 900; letter-spacing: 1px;")
        brand_layout.addWidget(logo_title)

        version_lbl = QLabel("v1.0.0 Enterprise Privacy", sidebar)
        version_lbl.setStyleSheet("font-size: 10px; color: #666666;")
        brand_layout.addWidget(version_lbl)
        side_layout.addLayout(brand_layout)
        side_layout.addSpacing(20)

        # Navigasyon Butonları
        self.btn_nav_dashboard = self._create_nav_button("🛡️ Gösterge Paneli", 0, active=True)
        self.btn_nav_forensics = self._create_nav_button("🧹 Adli Temizlik", 1)
        self.btn_nav_leak = self._create_nav_button("🔍 Sızıntı Testi", 2)
        self.btn_nav_settings = self._create_nav_button("⚙️ Ayarlar", 3)

        side_layout.addWidget(self.btn_nav_dashboard)
        side_layout.addWidget(self.btn_nav_forensics)
        side_layout.addWidget(self.btn_nav_leak)
        side_layout.addWidget(self.btn_nav_settings)
        side_layout.addStretch()

        # Acil Durum Panik Butonu (En altta kırmızı)
        self.btn_panic = QPushButton("🚨 PANİK BUTONU (NUKE)", sidebar)
        self.btn_panic.setObjectName("panicButton")
        self.btn_panic.setToolTip("Tüm ağ trafiğini anında keser, açık soketleri düşürür ve belleği temizler.")
        self.btn_panic.clicked.connect(self._trigger_panic)
        side_layout.addWidget(self.btn_panic)

        main_layout.addWidget(sidebar)

        # ---------------------------------------------------------------------
        # 2. Sağ İçerik Alanı (Stacked Widget)
        # ---------------------------------------------------------------------
        self.stacked_widget = QStackedWidget(self)

        # Sayfa 0: Gösterge Paneli (Dashboard)
        self.page_dashboard = self._create_dashboard_page()
        self.stacked_widget.addWidget(self.page_dashboard)

        # Sayfa 1: Adli Temizlik Paneli
        self.page_forensics = ForensicsPanel(self.client, self)
        self.page_forensics.cleanup_finished.connect(lambda d: self._poll_daemon_status())
        self.stacked_widget.addWidget(self.page_forensics)

        # Sayfa 2: Sızıntı Test Paneli
        self.page_leak = LeakPanel(self.client, self)
        self.stacked_widget.addWidget(self.page_leak)

        # Sayfa 3: Ayarlar Paneli
        self.page_settings = SettingsPanel(parent=self)
        self.page_settings.theme_changed.connect(self.apply_theme)
        self.stacked_widget.addWidget(self.page_settings)

        main_layout.addWidget(self.stacked_widget, stretch=1)

    def _create_nav_button(self, text: str, page_index: int, active: bool = False) -> QPushButton:
        """Sol kenar çubuğu navigasyon butonu oluşturur."""
        btn = QPushButton(text, self)
        btn.setProperty("class", "navButton")
        btn.setProperty("active", "true" if active else "false")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(lambda: self._switch_page(page_index, btn))
        return btn

    def _switch_page(self, index: int, active_btn: QPushButton) -> None:
        """Sayfa değiştirir ve aktif butonun stilini günceller."""
        self.stacked_widget.setCurrentIndex(index)
        for btn in [self.btn_nav_dashboard, self.btn_nav_forensics, self.btn_nav_leak, self.btn_nav_settings]:
            btn.setProperty("active", "true" if btn == active_btn else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)

    def _create_dashboard_page(self) -> QWidget:
        """Ana gösterge paneli sayfasını oluşturur."""
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # Üst Canlı Hız ve Durum Çubuğu
        self.speed_bar = NetSpeedBar(page)
        layout.addWidget(self.speed_bar)

        # Orta Alan: Durum Halkası ve Bağlan Butonları
        center_box = QFrame(page)
        center_box.setProperty("class", "cardFrame")
        center_layout = QVBoxLayout(center_box)
        center_layout.setContentsMargins(16, 20, 16, 20)
        center_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        center_layout.setSpacing(16)

        self.status_ring = StatusRingWidget(center_box)
        self.status_ring.clicked.connect(self._toggle_connection)
        center_layout.addWidget(self.status_ring, alignment=Qt.AlignmentFlag.AlignCenter)

        # Eylem Butonları Satırı
        action_btn_layout = QHBoxLayout()
        action_btn_layout.setSpacing(14)
        action_btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.btn_connect = QPushButton("🛡️ KORUMAYI BAŞLAT", center_box)
        self.btn_connect.setObjectName("primaryButton")
        self.btn_connect.setMinimumHeight(42)
        self.btn_connect.setMinimumWidth(180)
        self.btn_connect.clicked.connect(self._toggle_connection)
        action_btn_layout.addWidget(self.btn_connect)

        self.btn_new_circuit = QPushButton("🔄 YENİ KİMLİK (DEVRE YENİLE)", center_box)
        self.btn_new_circuit.setMinimumHeight(42)
        self.btn_new_circuit.clicked.connect(self._renew_circuit)
        action_btn_layout.addWidget(self.btn_new_circuit)

        center_layout.addLayout(action_btn_layout)
        layout.addWidget(center_box)

        # Alt Alan: 4 Servis Kartı (Grid / Yatay)
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.card_tor = ServiceCardWidget("Tor Ağı", "TCP yönlendirme ve .onion şeffaf proxy", "🧅", page)
        self.card_dns = ServiceCardWidget("DNSCrypt", "Şifreli DNS ve DoH bypass koruması", "🌐", page)
        self.card_mac = ServiceCardWidget("MAC Kalkanı", "In-place rastgele donanım adresi", "📡", page)
        self.card_forensics = ServiceCardWidget("Adli Temizlik", "Bellek ve log hijyen motoru", "🧹", page)

        cards_layout.addWidget(self.card_tor)
        cards_layout.addWidget(self.card_dns)
        cards_layout.addWidget(self.card_mac)
        cards_layout.addWidget(self.card_forensics)

        layout.addLayout(cards_layout)
        return page

    # -------------------------------------------------------------------------
    # Sistem Tepsisi (System Tray)
    # -------------------------------------------------------------------------
    def _init_tray_icon(self) -> None:
        """Sistem tepsisi simgesi ve sağ tık menüsünü hazırlar."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.windowIcon())
        self.tray_icon.setToolTip("AnonVoid — Koruma Hazır")

        from PyQt6.QtWidgets import QMenu

        tray_menu = QMenu()
        show_action = QAction("Göster / Gizle", self)
        show_action.triggered.connect(self._toggle_window_visibility)
        tray_menu.addAction(show_action)

        renew_action = QAction("Yeni Kimlik (Devre Yenile)", self)
        renew_action.triggered.connect(self._renew_circuit)
        tray_menu.addAction(renew_action)

        tray_menu.addSeparator()

        panic_action = QAction("🚨 ACİL PANİK / NUKE", self)
        panic_action.triggered.connect(self._trigger_panic)
        tray_menu.addAction(panic_action)

        tray_menu.addSeparator()

        quit_action = QAction("Çıkış", self)
        quit_action.triggered.connect(QApplication.instance().quit)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()

    def _toggle_window_visibility(self) -> None:
        if self.isVisible():
            self.hide()
        else:
            self.showNormal()
            self.activateWindow()

    # -------------------------------------------------------------------------
    # Tema Yönetimi
    # -------------------------------------------------------------------------
    def apply_theme(self, theme_key: str) -> None:
        """Uygulamanın genel stil sayfasını (QSS) seçilen temaya göre günceller."""
        self._current_theme = theme_key
        qss = get_theme_stylesheet(theme_key)
        self.setStyleSheet(qss)

    # -------------------------------------------------------------------------
    # Ağ Kalkanı Eylemleri ve Daemon İletişimi
    # -------------------------------------------------------------------------
    def _toggle_connection(self) -> None:
        """Korumayı açar veya kapatır."""
        if self._is_connected:
            self._disconnect_network()
        else:
            self._connect_network()

    def _connect_network(self) -> None:
        """Ağ kalkanını daemon üzerinden başlatır."""
        self.status_ring.set_status("CONNECTING")
        self.btn_connect.setEnabled(False)

        net_cfg = self.page_settings.config_data.get("network", {})

        def _on_success(data: Dict[str, Any]) -> None:
            self._is_connected = True
            self.status_ring.set_status("CONNECTED")
            self.btn_connect.setText("🛑 BAĞLANTIYI KES")
            self.btn_connect.setEnabled(True)
            self._update_service_cards(True)
            self.speed_bar.update_info("Tor TransPort Aktif", True)
            if hasattr(self, "tray_icon"):
                self.tray_icon.showMessage(
                    "AnonVoid Kalkanı Açık",
                    "Tüm giden internet trafiğiniz Tor ve şifreli DNSCrypt üzerinden yönlendiriliyor.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )

        def _on_error(err_msg: str) -> None:
            self.status_ring.set_status("OFFLINE")
            self.btn_connect.setEnabled(True)
            QMessageBox.warning(self, "Bağlantı Hatası", f"Ağ kalkanı başlatılamadı:\n{err_msg}")

        worker = AsyncDaemonWorker(
            client=self.client,
            action="connect",
            params={"network": net_cfg},
            timeout=25.0,
            on_success=_on_success,
            on_error=_on_error,
        )
        worker.start()

    def _disconnect_network(self) -> None:
        """Ağ kalkanını devreden çıkarır."""
        self.status_ring.set_status("CONNECTING")
        self.btn_connect.setEnabled(False)

        def _on_success(data: Dict[str, Any]) -> None:
            self._is_connected = False
            self.status_ring.set_status("OFFLINE")
            self.btn_connect.setText("🛡️ KORUMAYI BAŞLAT")
            self.btn_connect.setEnabled(True)
            self._update_service_cards(False)
            self.speed_bar.update_info("Yerel Ağ (Korumasız)", False)

        def _on_error(err_msg: str) -> None:
            self.btn_connect.setEnabled(True)
            QMessageBox.warning(self, "Hata", f"Bağlantı kesilirken hata oluştu:\n{err_msg}")

        worker = AsyncDaemonWorker(
            client=self.client,
            action="disconnect",
            timeout=15.0,
            on_success=_on_success,
            on_error=_on_error,
        )
        worker.start()

    def _renew_circuit(self) -> None:
        """Tor devre yenilemesini tetikler."""
        self.btn_new_circuit.setEnabled(False)

        def _on_success(data: Dict[str, Any]) -> None:
            self.btn_new_circuit.setEnabled(True)
            msg = data.get("message", "Yeni kimlik atandı.")
            QMessageBox.information(self, "Kimlik Rotasyonu", f"Tor Devresi Yenilendi:\n{msg}")

        def _on_error(err_msg: str) -> None:
            self.btn_new_circuit.setEnabled(True)
            QMessageBox.warning(self, "Hata", f"Devre yenilenemedi:\n{err_msg}")

        worker = AsyncDaemonWorker(
            client=self.client,
            action="new_circuit",
            timeout=10.0,
            on_success=_on_success,
            on_error=_on_error,
        )
        worker.start()

    def _trigger_panic(self) -> None:
        """Acil durum panik butonu onay ve yürütme mantığı."""
        reply = QMessageBox.question(
            self,
            "🚨 ACİL DURUM ONAYI",
            "PANİK BUTONUNU TETİKLEMEK ÜZERESİNİZ!\n\n"
            "• Tüm ağ bağlantıları anında bloke edilecek (Drop All),\n"
            "• Açık tüm TCP soketleri zorla kesilecek,\n"
            "• Terminal ve shell komut geçmişi ezilecek,\n"
            "• RAM önbellekleri boşaltılacak.\n\n"
            "Onaylıyor musunuz?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        self.status_ring.set_status("PANIC")

        def _on_success(data: Dict[str, Any]) -> None:
            self._is_connected = False
            self._update_service_cards(False)
            self.btn_connect.setText("🛡️ KORUMAYI BAŞLAT")
            self.speed_bar.update_info("TÜM AĞ KİLİTLENDİ (PANİK)", False)
            QMessageBox.critical(
                self,
                "Acil Durum Tamamlandı",
                "PANİK PROTOKOLÜ UYGULANDI:\n"
                "Ağ trafiği donduruldu, açık oturumlar ve izler temizlendi.",
            )

        def _on_error(err_msg: str) -> None:
            QMessageBox.critical(self, "Hata", f"Panik protokolü yürütülürken hata: {err_msg}")

        worker = AsyncDaemonWorker(
            client=self.client,
            action="panic",
            timeout=15.0,
            on_success=_on_success,
            on_error=_on_error,
        )
        worker.start()

    def _update_service_cards(self, active: bool) -> None:
        """Alt servis kartlarının durumlarını günceller."""
        self.card_tor.set_active(active, "TransPort 9040" if active else "Pasif")
        self.card_dns.set_active(active, "Şifreli 5380" if active else "Pasif")
        self.card_mac.set_active(active, "Randomize Edildi" if active else "Hazır")
        self.card_forensics.set_active(True, "Hazır")

    def _poll_daemon_status(self) -> None:
        """Arka plandaki daemon durumunu sorgular ve GUI'yi senkronize tutar."""
        def _on_success(data: Dict[str, Any]) -> None:
            shield_active = data.get("network_shield_active", False)
            if shield_active != self._is_connected:
                self._is_connected = shield_active
                self.status_ring.set_status("CONNECTED" if shield_active else "OFFLINE")
                self.btn_connect.setText("🛑 BAĞLANTIYI KES" if shield_active else "🛡️ KORUMAYI BAŞLAT")
                self._update_service_cards(shield_active)
                self.speed_bar.update_info("Tor TransPort Aktif" if shield_active else "Yerel Ağ (Korumasız)", shield_active)

        def _on_error(err_msg: str) -> None:
            # Daemon kapalı ise
            pass

        worker = AsyncDaemonWorker(
            client=self.client,
            action="status",
            timeout=3.0,
            on_success=_on_success,
            on_error=_on_error,
        )
        worker.start()
