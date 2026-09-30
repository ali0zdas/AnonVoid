"""AnonVoid - Ana Kontrol Merkezi ve Gösterge Paneli (Main Window).

Bu modül; sol kenar çubuğu navigasyonunu, üst uygulama çubuğunu, durum
halkasını, servis kartlarını, iki aşamalı acil durum panik butonunu, sistem
tepsisi entegrasyonunu ve daemon erişilebilirlik denetimini barındıran merkezi
kullanıcı arayüzüdür.

Arayüz ilkeleri:
* Daemon erişilemez durumunda sessizce "kapalı" gösterilmez; kullanıcıya açık
  bir uyarı şeridi ve devre dışı bırakılmış eylem denetimleri sunulur. Bir
  gizlilik aracında "korunduğunu sanmak" en tehlikeli hatadır.
* Panik (nuke) eylemi iki aşamalı onay ve geri sayımlı hazırlık ister.
* Tüm renkler `gui.themes` paletinden gelir.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QAction, QCloseEvent, QKeySequence
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
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
from gui.themes import get_theme_stylesheet, set_active_theme
from gui.widgets import (
    GLYPH_DNS,
    GLYPH_FORENSICS,
    GLYPH_LEAK,
    GLYPH_MAC,
    GLYPH_TOR,
    MetricTile,
    NetSpeedBar,
    PageHeader,
    ServiceCardWidget,
    StatusPill,
    StatusRingWidget,
    build_app_icon,
)

# Sekme başlıkları: (başlık, alt açıklama)
PAGE_META = [
    ("Gösterge Paneli", "Koruma durumunuz, servislerin ve kimlik parmak izinizin özeti."),
    ("Adli Temizlik", "Shell geçmişi, sistem günlükleri, önbellekler ve bellek hijyen modülleri."),
    ("Sızıntı Testi", "Tor çıkış IP'si, DNS, IPv6 ve WebRTC kaçaklarını gerçek zamanlı denetleyin."),
    ("Ayarlar", "Ağ omurgası portları, koruma ilkeleri ve görsel tema tercihleri."),
]

# Navigasyon etiketleri: metin + geometrik glif
NAV_ITEMS = [
    ("Gösterge Paneli", GLYPH_TOR, 0),
    ("Adli Temizlik", GLYPH_FORENSICS, 1),
    ("Sızıntı Testi", GLYPH_LEAK, 2),
    ("Ayarlar", "◆", 3),
]


class NoticeBanner(QFrame):
    """Uygulama genelinde gösterilen uyarı şeridi."""

    def __init__(self, token: str = "warning", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("noticeBanner")
        self.setProperty("token", token)
        self.setVisible(False)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 9, 12, 9)
        layout.setSpacing(10)

        self.text_label = QLabel("", self)
        self.text_label.setWordWrap(True)
        self.text_label.setObjectName("noticeText")
        layout.addWidget(self.text_label, stretch=1)

        self.action_label = QLabel("", self)
        self.action_label.setObjectName("noticeText")
        self.action_label.setVisible(False)
        layout.addWidget(self.action_label)

    def show_message(self, text: str, token: str = "warning", action: str = "") -> None:
        """Şeridi verilen mesaj ve anlam rengiyle görünür kılar."""
        self.setProperty("token", token)
        self.text_label.setText(text)
        self.action_label.setText(action)
        self.action_label.setVisible(bool(action))
        self.setVisible(True)
        self.style().unpolish(self)
        self.style().polish(self)

    def hide_message(self) -> None:
        self.setVisible(False)


class MainWindow(QMainWindow):
    """AnonVoid Ana Masaüstü Arayüzü."""

    def __init__(self, client: Optional[DaemonClient] = None) -> None:
        super().__init__()
        self.client = client or DaemonClient()

        # Root GUI Güvenlik Engeli (AGENTS.md ve Wayland Kuralı)
        if hasattr(os, "getuid") and os.getuid() == 0:
            QMessageBox.critical(
                None,
                "Güvenlik Uyarısı (Ayrıcalık İhlali)",
                "AnonVoid grafik arayüzü asla root veya sudo ile çalıştırılamaz.\n"
                "Lütfen uygulamayı normal kullanıcı oturumunuzdan başlatın.\n"
                "Sistem düzeyindeki işlemler arka plandaki anonvoid daemon'a iletilecektir.",
            )
            sys.exit(1)

        self.setWindowTitle("AnonVoid — Dijital Ayak İzi ve Ağ Gizliliği")
        self.setMinimumSize(1040, 680)
        self.resize(1180, 720)
        self.setWindowIcon(build_app_icon(64))

        self._current_theme = "oled"
        self._is_connected = False
        self._daemon_online = False
        self._panic_armed = False
        self._mac_state = "—"
        self._forensics_state = "Beklemede"

        self._init_ui()
        self._init_tray_icon()
        self._init_shortcuts()
        self.apply_theme(self._current_theme)

        # Periyodik daemon durum zamanlayıcısı
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_daemon_status)
        self._poll_timer.start(3000)

        # Panik butonu hazırlık sayacı
        self._panic_timer = QTimer(self)
        self._panic_timer.setSingleShot(True)
        self._panic_timer.timeout.connect(self._disarm_panic)

        self._poll_daemon_status()

    # ------------------------------------------------------------------
    # Arayüz kurulumu
    # ------------------------------------------------------------------
    def _init_ui(self) -> None:
        root = QWidget(self)
        root.setObjectName("rootPane")
        self.setCentralWidget(root)

        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        outer.addWidget(self._build_sidebar())

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self._build_app_bar())
        right.addWidget(self._build_banner_holder())

        self.stacked_widget = QStackedWidget(self)
        self.stacked_widget.addWidget(self._create_dashboard_page())
        self.stacked_widget.addWidget(ForensicsPanel(self.client, self))
        self.stacked_widget.addWidget(LeakPanel(self.client, self))
        self.stacked_widget.addWidget(SettingsPanel(parent=self))
        right.addWidget(self.stacked_widget, stretch=1)
        outer.addLayout(right, stretch=1)

        for panel, page_index in ((self.stacked_widget.widget(1), 1), (self.stacked_widget.widget(2), 2)):
            finished = getattr(panel, "cleanup_finished", None)
            if finished is not None:
                finished.connect(lambda *_: self._poll_daemon_status())
        self.stacked_widget.widget(3).theme_changed.connect(self.apply_theme)
        self.page_settings = self.stacked_widget.widget(3)

    def _build_sidebar(self) -> QFrame:
        """Sol kenar çubuğunu oluşturur."""
        sidebar = QFrame(self)
        sidebar.setObjectName("sidebarFrame")
        sidebar.setFixedWidth(228)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 18, 0, 16)
        layout.setSpacing(0)

        brand = QWidget(sidebar)
        brand_layout = QVBoxLayout(brand)
        brand_layout.setContentsMargins(18, 0, 18, 0)
        brand_layout.setSpacing(1)
        title = QLabel("ANONVOID", brand)
        title.setObjectName("sidebarTitle")
        subtitle = QLabel("Dijital Ayak İzi ve Ağ Gizliliği", brand)
        subtitle.setObjectName("sidebarSubtitle")
        subtitle.setWordWrap(True)
        brand_layout.addWidget(title)
        brand_layout.addWidget(subtitle)
        layout.addWidget(brand)

        section = QLabel("NAVİGASYON", sidebar)
        section.setObjectName("sidebarSection")
        layout.addSpacing(22)
        layout.addWidget(section)
        layout.addSpacing(6)

        self._nav_buttons = []
        nav = QWidget(sidebar)
        nav_layout = QVBoxLayout(nav)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(2)
        for label, glyph, index in NAV_ITEMS:
            btn = QPushButton(f"  {glyph}   {label}", nav)
            btn.setProperty("class", "navButton")
            btn.setProperty("active", "true" if index == 0 else "false")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(f"{label}  (Ctrl+{index + 1})")
            btn.clicked.connect(lambda _=False, i=index, b=btn: self._switch_page(i, b))
            nav_layout.addWidget(btn)
            self._nav_buttons.append(btn)
        layout.addWidget(nav)

        layout.addStretch(1)

        self.panic_hint = QLabel("", sidebar)
        self.panic_hint.setObjectName("panicArmLabel")
        self.panic_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.panic_hint.setWordWrap(True)
        self.panic_hint.setVisible(False)
        layout.addWidget(self.panic_hint)

        self.btn_panic = QPushButton("PANİK / NUKE", sidebar)
        self.btn_panic.setObjectName("panicButton")
        self.btn_panic.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_panic.setToolTip(
            "Tüm ağ trafiğini anında keser, açık soketleri düşürür ve belleği temizler.\n"
            "Yanlışlıkla tetiklenmemesi için iki kez onay ister."
        )
        self.btn_panic.clicked.connect(self._trigger_panic)
        layout.addWidget(self.btn_panic)

        # Test sözleşmesi: butonlar doğrudan erişilebilir olmalı
        self.btn_nav_dashboard = self._nav_buttons[0]
        self.btn_nav_forensics = self._nav_buttons[1]
        self.btn_nav_leak = self._nav_buttons[2]
        self.btn_nav_settings = self._nav_buttons[3]
        return sidebar

    def _build_app_bar(self) -> QWidget:
        """Üst uygulama çubuğunu oluşturur: sayfa başlığı ve canlı durum fişi."""
        bar = QFrame(self)
        bar.setObjectName("appBar")
        bar.setFixedHeight(62)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(16)

        text_col = QVBoxLayout()
        text_col.setSpacing(1)
        self.app_bar_title = QLabel("", bar)
        self.app_bar_title.setObjectName("appBarTitle")
        self.app_bar_subtitle = QLabel("", bar)
        self.app_bar_subtitle.setObjectName("appBarSubtitle")
        text_col.addWidget(self.app_bar_title)
        text_col.addWidget(self.app_bar_subtitle)
        layout.addLayout(text_col, stretch=1)

        self.daemon_pill = StatusPill("Bağlanıyor…", "text_muted", bar)
        layout.addWidget(self.daemon_pill, alignment=Qt.AlignmentFlag.AlignVCenter)
        return bar

    def _build_banner_holder(self) -> QWidget:
        """Uyarı şeridini bar ile içerik arasına yerleştiren kapsayıcıyı kurar."""
        holder = QWidget(self)
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(24, 12, 24, 0)
        layout.setSpacing(0)
        self.banner = NoticeBanner("warning", holder)
        layout.addWidget(self.banner)
        return holder

    # ------------------------------------------------------------------
    # Gösterge paneli (Dashboard)
    # ------------------------------------------------------------------
    def _create_dashboard_page(self) -> QWidget:
        """Ana gösterge paneli sayfasını oluşturur."""
        page = QWidget(self)
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 22)
        layout.setSpacing(16)

        self.speed_bar = NetSpeedBar(page)
        layout.addWidget(self.speed_bar)

        # Kahraman alanı: durum halkası + ölçümler + eylemler
        hero = QFrame(page)
        hero.setProperty("class", "cardFrame")
        hero_layout = QHBoxLayout(hero)
        hero_layout.setContentsMargins(20, 20, 20, 20)
        hero_layout.setSpacing(28)

        self.status_ring = StatusRingWidget(hero)
        self.status_ring.clicked.connect(self._toggle_connection)
        self.status_ring.setToolTip("Kalkanı açmak veya kapatmak için tıklayın  (Ctrl+K)")
        hero_layout.addWidget(self.status_ring, alignment=Qt.AlignmentFlag.AlignCenter)

        right_col = QVBoxLayout()
        right_col.setSpacing(16)

        metrics_label = QLabel("CANLI DURUM", hero)
        metrics_label.setObjectName("sectionTitle")
        right_col.addWidget(metrics_label)

        metrics = QGridLayout()
        metrics.setSpacing(10)
        self.tile_tor = MetricTile("TOR", "Bilinmiyor", "text_muted", hero)
        self.tile_dns = MetricTile("DNSCRYPT", "Bilinmiyor", "text_muted", hero)
        self.tile_renewal = MetricTile("SON KİMLİK", "—", "text_muted", hero)
        self.tile_uptime = MetricTile("SERVİS SÜRESİ", "—", "text_muted", hero)
        metrics.addWidget(self.tile_tor, 0, 0)
        metrics.addWidget(self.tile_dns, 0, 1)
        metrics.addWidget(self.tile_renewal, 1, 0)
        metrics.addWidget(self.tile_uptime, 1, 1)
        right_col.addLayout(metrics)

        actions = QHBoxLayout()
        actions.setSpacing(10)

        self.btn_connect = QPushButton("KORUMAYI BAŞLAT", hero)
        self.btn_connect.setObjectName("primaryButton")
        self.btn_connect.setMinimumHeight(42)
        self.btn_connect.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_connect.setToolTip("Tor, DNSCrypt, güvenlik duvarı ve MAC kalkanını birlikte devreye alır  (Ctrl+K)")
        self.btn_connect.clicked.connect(self._toggle_connection)
        actions.addWidget(self.btn_connect, stretch=1)

        self.btn_new_circuit = QPushButton("YENİ KİMLİK", hero)
        self.btn_new_circuit.setObjectName("ghostButton")
        self.btn_new_circuit.setMinimumHeight(42)
        self.btn_new_circuit.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_new_circuit.setToolTip("Tor devresini yeniler ve çıkış düğümünü değiştirir")
        self.btn_new_circuit.clicked.connect(self._renew_circuit)
        actions.addWidget(self.btn_new_circuit)
        right_col.addLayout(actions)

        hero_layout.addLayout(right_col, stretch=1)
        layout.addWidget(hero)

        # Servis kartları
        services_label = QLabel("SERVİSLER", page)
        services_label.setObjectName("sectionTitle")
        layout.addWidget(services_label)

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_tor = ServiceCardWidget(
            "Tor Ağı", "TCP yönlendirme ve şeffaf proxy", GLYPH_TOR, page
        )
        self.card_dns = ServiceCardWidget(
            "DNSCrypt", "Şifreli DNS ve DoH engelleme", GLYPH_DNS, page
        )
        self.card_mac = ServiceCardWidget(
            "MAC Kalkanı", "Rastgele donanım adresi", GLYPH_MAC, page
        )
        self.card_forensics = ServiceCardWidget(
            "Adli Temizlik", "Bellek ve günlük hijyen motoru", GLYPH_FORENSICS, page
        )
        for card in (self.card_tor, self.card_dns, self.card_mac, self.card_forensics):
            cards.addWidget(card)
        layout.addLayout(cards)
        layout.addStretch(1)
        return page

    # ------------------------------------------------------------------
    # Sayfa geçişi
    # ------------------------------------------------------------------
    def _switch_page(self, index: int, active_btn: QPushButton) -> None:
        """Sayfa değiştirir, etkin gezinme öğesini ve başlık çubuğunu günceller."""
        self.stacked_widget.setCurrentIndex(index)
        for btn in self._nav_buttons:
            btn.setProperty("active", "true" if btn == active_btn else "false")
            btn.style().unpolish(btn)
            btn.style().polish(btn)
        if 0 <= index < len(PAGE_META):
            title, subtitle = PAGE_META[index]
            self.app_bar_title.setText(title)
            self.app_bar_subtitle.setText(subtitle)

    def _init_shortcuts(self) -> None:
        """Klavye kısayollarını tanımlar."""
        for index, button in enumerate(self._nav_buttons, start=1):
            QAction(
                f"Sayfa {index}",
                self,
                shortcut=QKeySequence(f"Ctrl+{index}"),
                triggered=lambda _=False, i=index - 1, b=button: self._switch_page(i, b),
            )
        QAction(self, shortcut=QKeySequence("Ctrl+K"), triggered=self._toggle_connection)
        QAction(
            self,
            shortcut=QKeySequence("Ctrl+L"),
            triggered=lambda: self._switch_page(2, self.btn_nav_leak),
        )
        QAction(self, shortcut=QKeySequence("Ctrl+Q"), triggered=QApplication.instance().quit)

    # ------------------------------------------------------------------
    # Sistem tepsisi
    # ------------------------------------------------------------------
    def _init_tray_icon(self) -> None:
        """Sistem tepsisi simgesi ve sağ tık menüsünü hazırlar."""
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(build_app_icon(22, "accent"))
        self.tray_icon.setToolTip("AnonVoid")

        menu = QMenu()
        show_action = QAction("Göster / Gizle", self)
        show_action.triggered.connect(self._toggle_window_visibility)
        menu.addAction(show_action)

        renew_action = QAction("Yeni Kimlik (Devre Yenile)", self)
        renew_action.triggered.connect(self._renew_circuit)
        menu.addAction(renew_action)

        menu.addSeparator()
        panic_action = QAction("Acil Durum Panik / Nuke", self)
        panic_action.triggered.connect(self._trigger_panic)
        menu.addAction(panic_action)
        menu.addSeparator()

        quit_action = QAction("Çıkış", self)
        quit_action.triggered.connect(QApplication.instance().quit)
        menu.addAction(quit_action)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(
            lambda reason: self._toggle_window_visibility()
            if reason == QSystemTrayIcon.ActivationReason.Trigger
            else None
        )
        self.tray_icon.show()

    def _toggle_window_visibility(self) -> None:
        if self.isVisible():
            self.hide()
        else:
            self.showNormal()
            self.activateWindow()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        """Kapatma isteğinde arka planda çalışmaya devam edip tepsiye küçülür."""
        if getattr(self, "tray_icon", None) is not None and self.tray_icon.isVisible():
            self.hide()
            event.ignore()
            return
        event.accept()

    # ------------------------------------------------------------------
    # Tema yönetimi
    # ------------------------------------------------------------------
    def apply_theme(self, theme_key: str) -> None:
        """Uygulamanın stil sayfasını seçilen temaya göre günceller."""
        self._current_theme = set_active_theme(theme_key)
        self.setStyleSheet(get_theme_stylesheet(self._current_theme))
        if getattr(self, "tray_icon", None) is not None:
            self.tray_icon.setIcon(build_app_icon(22, "accent"))
        if getattr(self, "status_ring", None) is not None:
            self.status_ring.set_status(self.status_ring._status)

    # ------------------------------------------------------------------
    # Daemon erişilebilirliği
    # ------------------------------------------------------------------
    def _set_daemon_state(self, online: bool, detail: str = "") -> None:
        """Daemon erişilebilirliğini arayüze yansıtır.

        Erişilemediğinde kalkan durumu "kapalı" gibi gösterilmez; kullanıcıya
        korunmadığı açıkça bildirilir. Erişilebilirlik yeniden kazanıldığında
        devre dışı bırakılmış denetimler geri açılır.
        """
        if online:
            self._daemon_online = True
            self.daemon_pill.set_state("Daemon bağlı", "success")
            self.banner.hide_message()
            self._apply_shield_state(self._is_connected)
            return

        self._daemon_online = False
        self.daemon_pill.set_state("Daemon yok", "danger")
        self.status_ring.set_status("UNAVAILABLE")
        self.speed_bar.set_state("warning")
        self.speed_bar.update_info("Denetim yapılamıyor", False, detail)
        self.btn_connect.setText("DAEMON ÇALIŞMIYOR")
        self.btn_connect.setEnabled(False)
        self.btn_new_circuit.setEnabled(False)
        self.tile_tor.set_value("Bilinmiyor", "text_muted")
        self.tile_dns.set_value("Bilinmiyor", "text_muted")
        self._update_service_cards(False)
        self.banner.show_message(
            "AnonVoid daemon servisine ulaşılamıyor — kalkan denetlenemiyor ve "
            "trafiğiniz korumasız olabilir. Kök terminalde "
            "'sudo systemctl start anonvoid' ile servisi başlatın.",
            token="danger",
        )

    def _poll_daemon_status(self) -> None:
        """Daemon durumunu periyodik olarak sorgular ve arayüzü senkronize eder."""

        def _on_success(data: Dict[str, Any]) -> None:
            # Kalkan durumu her zaman yeniden uygulanır: daemon çevrimdışıyken
            # devre dışı bırakılan denetimler, servis geri geldiğinde aksi
            # hâlde kalıcı olarak pasif kalırdı.
            self._is_connected = bool(data.get("network_shield_active", False))
            self._set_daemon_state(True)
            self._update_metrics(data)

        def _on_error(err_msg: str) -> None:
            self._set_daemon_state(False, err_msg)

        AsyncDaemonWorker(
            client=self.client,
            action="status",
            timeout=3.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _apply_shield_state(self, active: bool) -> None:
        """Kalkanın açık/kapalı durumunu tüm görsel bileşenlere yansıtır."""
        self._is_connected = active
        self.status_ring.set_status("CONNECTED" if active else "OFFLINE")
        self.btn_connect.setText("BAĞLANTIYI KES" if active else "KORUMAYI BAŞLAT")
        self.btn_connect.setEnabled(self._daemon_online)
        self.btn_new_circuit.setEnabled(self._daemon_online and active)
        self._update_service_cards(active)
        if active:
            self.speed_bar.update_info("Tor devresi kuruldu", True, "Ayrıntı için sızıntı testini çalıştırın")
        else:
            self.speed_bar.update_info("Kalkan kapalı", False, "Dış IP'niz doğrudan ifşa ediliyor")

    def _update_metrics(self, data: Dict[str, Any]) -> None:
        """Daemon durumundan doğrulanan değerleri ölçüm kutularına yazar."""
        tor_ok = bool(data.get("tor_active", False))
        dns_ok = bool(data.get("dnscrypt_active", False))
        self.tile_tor.set_value("Aktif" if tor_ok else "Pasif", "success" if tor_ok else "warning")
        self.tile_dns.set_value("Aktif" if dns_ok else "Pasif", "success" if dns_ok else "warning")

        renewal = float(data.get("last_circuit_renewal", 0.0) or 0.0)
        if renewal > 0:
            self.tile_renewal.set_value(
                time.strftime("%H:%M:%S", time.localtime(renewal)), "text_primary"
            )
        else:
            self.tile_renewal.set_value("Henüz yenilenmedi", "text_muted")

        uptime = data.get("uptime_sec")
        if isinstance(uptime, (int, float)) and uptime >= 0:
            total = int(uptime)
            self.tile_uptime.set_value(f"{total // 3600} sa {total % 3600 // 60} dk", "text_primary")

        cleanup = float(data.get("last_forensics_cleanup", 0.0) or 0.0)
        if cleanup > 0:
            self.card_forensics.set_state("Çalıştırıldı", "success")
        else:
            self.card_forensics.set_state("Beklemede", "text_muted")

    def _update_service_cards(self, active: bool) -> None:
        """Servis kartlarının durum rozetlerini günceller."""
        self.card_tor.set_state("Aktif" if active else "Pasif", "success" if active else "text_muted")
        self.card_dns.set_state("Aktif" if active else "Pasif", "success" if active else "text_muted")
        self.card_mac.set_state(self._mac_state, "success" if self._mac_state == "Uygulandı" else "text_muted")

    # ------------------------------------------------------------------
    # Ağ kalkanı eylemleri
    # ------------------------------------------------------------------
    def _toggle_connection(self) -> None:
        if not self._daemon_online:
            return
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
            mac_results = data.get("mac_randomized", {})
            self._mac_state = "Uygulandı" if mac_results else "Uygulanmadı"
            self.btn_connect.setEnabled(True)
            self._apply_shield_state(bool(data.get("connected", False)))
            if getattr(self, "tray_icon", None) is not None:
                self.tray_icon.showMessage(
                    "AnonVoid Kalkanı Açık",
                    "Tüm giden internet trafiğiniz Tor ve şifreli DNSCrypt üzerinden yönlendiriliyor.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )

        def _on_error(err_msg: str) -> None:
            self.status_ring.set_status("OFFLINE")
            self.btn_connect.setEnabled(self._daemon_online)
            QMessageBox.warning(self, "Bağlantı Hatası", f"Ağ kalkanı başlatılamadı:\n{err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="connect",
            params={"network": net_cfg},
            timeout=25.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _disconnect_network(self) -> None:
        """Ağ kalkanını güvenle devreden çıkarır."""
        self.btn_connect.setEnabled(False)

        def _on_success(data: Dict[str, Any]) -> None:
            self.btn_connect.setEnabled(True)
            self._mac_state = "—"
            self._apply_shield_state(False)

        def _on_error(err_msg: str) -> None:
            self.btn_connect.setEnabled(self._daemon_online)
            QMessageBox.warning(self, "Hata", f"Bağlantı kesilirken hata oluştu:\n{err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="disconnect",
            timeout=15.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _renew_circuit(self) -> None:
        """Tor devre yenilemesini tetikler."""
        if not self._daemon_online:
            return
        self.btn_new_circuit.setEnabled(False)

        def _on_success(data: Dict[str, Any]) -> None:
            self.btn_new_circuit.setEnabled(self._is_connected)
            QMessageBox.information(
                self, "Kimlik Rotasyonu", f"Tor devresi yenilendi:\n{data.get('message', 'Yeni çıkış düğümü atandı.')}"
            )

        def _on_error(err_msg: str) -> None:
            self.btn_new_circuit.setEnabled(self._is_connected)
            QMessageBox.warning(self, "Hata", f"Devre yenilenemedi:\n{err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="new_circuit",
            timeout=10.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    # ------------------------------------------------------------------
    # İki aşamalı panik protokolü
    # ------------------------------------------------------------------
    def _trigger_panic(self) -> None:
        """Panik eylemini iki aşamalı onay ile başlatır.

        İlk tıklama yalnızca butonu "hazır" durumuna geçirir ve geri sayım
        başlatır. Yanlışlıkla tetiklenmeyi önlemek için ikinci tıklama
        gerekmektedir.
        """
        if not self._panic_armed:
            self._panic_armed = True
            self.btn_panic.setText("TEKRAR BAS → ONAYLA")
            self.panic_hint.setText("Onaylamak için tekrar basın.\nBu işlem geri alınamaz.")
            self.panic_hint.setVisible(True)
            self._panic_timer.start(5000)
            return

        self._disarm_panic()
        self._confirm_and_execute_panic()

    def _disarm_panic(self) -> None:
        """Panik butonunun hazır durumunu ve geri sayımı temizler."""
        self._panic_timer.stop()
        self._panic_armed = False
        self.btn_panic.setText("PANİK / NUKE")
        self.panic_hint.setVisible(False)

    def _confirm_and_execute_panic(self) -> None:
        """Panik protokolü için nihai onay ister ve daemon'a iletir."""
        reply = QMessageBox.warning(
            self,
            "Acil Durum Onayı",
            "PANİK PROTOKOLÜ TETİKLENMEK ÜZERESİNİZ.\n\n"
            "• Tüm ağ bağlantıları anında bloke edilecek,\n"
            "• Açık tüm TCP soketleri zorla kesilecek,\n"
            "• Terminal ve kabuk komut geçmişi ezilecek,\n"
            "• RAM önbellekleri boşaltılacak.\n\n"
            "Bu işlem geri alınamaz. Devam edilsin mi?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.status_ring.set_status("PANIC")

        def _on_success(data: Dict[str, Any]) -> None:
            self._mac_state = "—"
            self._apply_shield_state(False)
            self.status_ring.set_status("PANIC")
            self.speed_bar.set_state("danger")
            self.speed_bar.update_info("Tüm ağ kilitlendi", False, "Panik protokolü uygulandı")
            QMessageBox.critical(
                self,
                "Acil Durum Tamamlandı",
                "PANİK PROTOKOLÜ UYGULANDI:\nAğ trafiği donduruldu, açık oturumlar ve izler temizlendi.",
            )

        def _on_error(err_msg: str) -> None:
            self._apply_shield_state(False)
            QMessageBox.critical(self, "Hata", f"Panik protokolü yürütülürken hata: {err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="panic",
            timeout=15.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()
