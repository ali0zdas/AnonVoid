"""AnonVoid - Ana Kontrol Merkezi ve Profesyonel Siber Güvenlik Gösterge Paneli.

Bu modül; sol kenar çubuğu navigasyonunu, üst uygulama çubuğunu, canlı siber kalkan
durum halkasını, gerçek zamanlı ağ trafiği analitiğini, canlı KPI metriklerini,
servis kartlarını, iki aşamalı acil durum panik butonunu, sistem tepsisi
entegrasyonunu ve daemon erişilebilirlik denetimini barındıran merkezi kullanıcı
arayüzüdür.

Arayüz ilkeleri:
* Daemon erişilemez durumunda sessizce "kapalı" gösterilmez; kullanıcıya açık
  bir uyarı şeridi ve devre dışı bırakılmış eylem denetimleri sunulur.
* Panik (nuke) eylemi iki aşamalı onay ve geri sayımlı hazırlık ister.
* Tüm renkler `gui.themes` paletinden gelir.
* Türkçe karakterlerin (`ş, ı, ğ, ç, ö, ü`) tamamı eksiksiz ve doğru kullanılır.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtCore import QSize, QTimer, Qt
from PyQt6.QtGui import QAction, QCloseEvent, QFont, QKeySequence
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
    QScrollArea,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from core.config import safe_load_config, safe_save_config
from core.daemon_client import AsyncDaemonWorker, DaemonClient
from gui.fonts import load_bundled_fonts
from gui.forensics_panel import ForensicsPanel
from gui.icons import make_icon
from gui.leak_panel import LeakPanel
from gui.settings_panel import SettingsPanel
from gui.themes import UI_FONT_STACK, current_palette, get_theme_stylesheet, set_active_theme
from gui.widgets import (
    GLYPH_DNS,
    GLYPH_FORENSICS,
    GLYPH_LEAK,
    GLYPH_MAC,
    GLYPH_TOR,
    LiveTrafficChart,
    MetricTile,
    NetSpeedBar,
    PageHeader,
    ServiceCardWidget,
    StatusPill,
    StatusRingWidget,
    _apply_font,
    build_app_icon,
    guarded_style_sheet,
)

# Gezinme ikonları (vektörel; gui.icons içinde tanımlı)
NAV_ICONS = ("dashboard", "forensics", "leak", "settings")
SERVICE_ICONS = {
    "tor": "network",
    "dns": "dns",
    "mac": "mac",
    "forensics": "forensics",
}

# Sekme başlıkları: (başlık, alt açıklama)
PAGE_META = [
    ("Gösterge Paneli", "Koruma durumunuz, canlı ağ akışı, servisler ve parmak izi özeti."),
    ("Adli Temizlik", "Shell geçmişi, sistem günlükleri, önbellekler ve bellek hijyen modülleri."),
    ("Sızıntı Testi", "Tor çıkış IP'si, DNS, IPv6 ve WebRTC kaçaklarını gerçek zamanlı denetleyin."),
    ("Ayarlar", "Ağ omurgası portları, sızıntı koruma kuralları ve uygulama tercihleri."),
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
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(10)

        self.text_label = QLabel("", self)
        self.text_label.setWordWrap(True)
        self.text_label.setObjectName("noticeText")
        _apply_font(self.text_label, 9, QFont.Weight.Medium)
        layout.addWidget(self.text_label, stretch=1)

        self.action_label = QLabel("", self)
        self.action_label.setObjectName("noticeText")
        self.action_label.setVisible(False)
        _apply_font(self.action_label, 9, QFont.Weight.Bold)
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
    """AnonVoid Ana Masaüstü Arayüzü ve Siber Güvenlik Kontrol Merkezi."""

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

        self.setWindowTitle("AnonVoid — Siber Güvenlik ve Gizlilik Kontrol Merkezi")
        self.setMinimumSize(1120, 700)
        self.resize(1280, 800)
        self.setWindowIcon(build_app_icon(64))

        # Gömülü Inter yazı tipini yükle (QApplication oluştuktan sonra).
        # Sistemde Inter kurulu olmasa bile tipografi tutarlı kalır.
        load_bundled_fonts()

        self.config_path = os.path.expanduser("~/.config/anonvoid/config.json")
        self.current_config = safe_load_config(self.config_path, fallback_to_default=True)

        self._current_theme = "oled"
        self._is_connected = False
        # Bir kalkan işlemi (bağlan/kes) sürerken periyodik durum yoklamasının
        # arayüzü geri almaması için kullanılan bayrak ve sürüm sayacı.
        self._shield_op_in_progress = False
        self._shield_epoch = 0
        self._daemon_online = False
        self._panic_armed = False
        self._mac_state = "—"
        self._forensics_state = "Beklemede"

        # Durum yoklama kilit bayrağı ve arka plan işçisi
        self._poll_in_flight = False
        self._poll_worker = None

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

        # Üst bar saat zamanlayıcısı
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(self._tick_clock)
        self._clock_timer.start(1000)
        self._tick_clock()

        QTimer.singleShot(0, self._poll_daemon_status)

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
        self.forensics_panel = ForensicsPanel(self.client, self)
        self.stacked_widget.addWidget(self.forensics_panel)
        self.leak_panel = LeakPanel(self.client, self)
        self.stacked_widget.addWidget(self.leak_panel)
        self.settings_panel = SettingsPanel(parent=self)
        self.stacked_widget.addWidget(self.settings_panel)
        right.addWidget(self.stacked_widget, stretch=1)
        outer.addLayout(right, stretch=1)

        for panel in (self.forensics_panel, self.leak_panel):
            finished = getattr(panel, "cleanup_finished", None)
            if finished is not None:
                finished.connect(lambda *_: self._poll_daemon_status())
        self.settings_panel.theme_changed.connect(self.apply_theme)
        self.settings_panel.config_saved.connect(self._on_settings_saved)
        self.page_settings = self.settings_panel

    def _build_sidebar(self) -> QFrame:
        """Sol kenar çubuğunu oluşturur."""
        sidebar = QFrame(self)
        sidebar.setObjectName("sidebarFrame")
        sidebar.setFixedWidth(236)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 20, 0, 18)
        layout.setSpacing(0)

        # Marka Kilidi: vektörel logo + ad + sürüm
        brand = QWidget(sidebar)
        brand_row = QHBoxLayout(brand)
        brand_row.setContentsMargins(18, 0, 16, 0)
        brand_row.setSpacing(11)

        logo = QLabel(brand)
        logo.setPixmap(build_app_icon(36, "accent").pixmap(36, 36))
        logo.setFixedSize(36, 36)
        brand_row.addWidget(logo, alignment=Qt.AlignmentFlag.AlignVCenter)

        brand_text = QVBoxLayout()
        brand_text.setSpacing(1)

        title = QLabel("ANONVOID", brand)
        title.setObjectName("sidebarTitle")
        _apply_font(title, 14, QFont.Weight.Bold, letter_spacing=1.6)

        subtitle = QLabel("Siber Güvenlik & Gizlilik", brand)
        subtitle.setObjectName("sidebarSubtitle")
        _apply_font(subtitle, 8, QFont.Weight.Medium)

        brand_text.addWidget(title)
        brand_text.addWidget(subtitle)
        brand_row.addLayout(brand_text, stretch=1)
        layout.addWidget(brand)

        version_row = QHBoxLayout()
        version_row.setContentsMargins(20, 9, 20, 0)
        badge_ver = QLabel("SÜRÜM 1.2.0", sidebar)
        badge_ver.setObjectName("sidebarVersion")
        _apply_font(badge_ver, 7, QFont.Weight.Bold, letter_spacing=1.0)
        version_row.addWidget(badge_ver)
        version_row.addStretch(1)
        layout.addLayout(version_row)

        section = QLabel("NAVİGASYON", sidebar)
        section.setObjectName("sidebarSection")
        _apply_font(section, 7, QFont.Weight.Bold, letter_spacing=1.3)
        layout.addSpacing(26)
        layout.addWidget(section)
        layout.addSpacing(8)

        self._nav_buttons = []
        nav = QWidget(sidebar)
        nav_layout = QVBoxLayout(nav)
        nav_layout.setContentsMargins(0, 0, 0, 0)
        nav_layout.setSpacing(3)
        for label, _glyph, index in NAV_ITEMS:
            btn = QPushButton(label, nav)
            btn.setProperty("class", "navButton")
            btn.setProperty("active", "true" if index == 0 else "false")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setIconSize(QSize(18, 18))
            btn.setMinimumHeight(38)
            # Gezinme düğmeleri klavye kısayollarıyla (Ctrl+1..4) erişilir;
            # fare tıklamasında odak çerçevesi görsel kirlilik yaratmasın.
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn.setToolTip(f"{label}  (Ctrl+{index + 1})")
            btn.clicked.connect(lambda _=False, i=index, b=btn: self._switch_page(i, b))
            nav_layout.addWidget(btn)
            self._nav_buttons.append(btn)
        layout.addWidget(nav)
        self._sync_nav_icons()

        layout.addStretch(1)

        # Panik Butonu Alanı
        panic_box = QWidget(sidebar)
        p_layout = QVBoxLayout(panic_box)
        p_layout.setContentsMargins(14, 0, 14, 0)
        p_layout.setSpacing(6)

        self.panic_hint = QLabel("", panic_box)
        self.panic_hint.setObjectName("panicArmLabel")
        self.panic_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.panic_hint.setWordWrap(True)
        self.panic_hint.setVisible(False)
        _apply_font(self.panic_hint, 8, QFont.Weight.Bold)
        p_layout.addWidget(self.panic_hint)

        self.btn_panic = QPushButton("PANİK / NUKE", panic_box)
        self.btn_panic.setObjectName("panicButton")
        self.btn_panic.setIcon(make_icon("alert", 16, "danger"))
        self.btn_panic.setIconSize(QSize(16, 16))
        self.btn_panic.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_panic.setToolTip(
            "Tüm ağ trafiğini anında keser, açık soketleri düşürür ve belleği temizler.\n"
            "Yanlışlıkla tetiklenmemesi için iki kez onay ister."
        )
        self.btn_panic.clicked.connect(self._trigger_panic)
        p_layout.addWidget(self.btn_panic)
        layout.addWidget(panic_box)

        # Test sözleşmesi: butonlar doğrudan erişilebilir olmalı
        self.btn_nav_dashboard = self._nav_buttons[0]
        self.btn_nav_forensics = self._nav_buttons[1]
        self.btn_nav_leak = self._nav_buttons[2]
        self.btn_nav_settings = self._nav_buttons[3]
        return sidebar

    def _build_app_bar(self) -> QWidget:
        """Üst uygulama çubuğunu oluşturur: sayfa başlığı, sistem saati ve canlı durum fişleri."""
        bar = QFrame(self)
        bar.setObjectName("appBar")
        bar.setFixedHeight(64)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)
        layout.setSpacing(16)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)
        self.app_bar_title = QLabel("Gösterge Paneli", bar)
        self.app_bar_title.setObjectName("appBarTitle")
        _apply_font(self.app_bar_title, 13, QFont.Weight.Bold)

        self.app_bar_subtitle = QLabel("Koruma durumunuz, canlı ağ akışı, servisler ve parmak izi özeti.", bar)
        self.app_bar_subtitle.setObjectName("appBarSubtitle")
        _apply_font(self.app_bar_subtitle, 8, QFont.Weight.Normal)

        text_col.addWidget(self.app_bar_title)
        text_col.addWidget(self.app_bar_subtitle)
        layout.addLayout(text_col, stretch=1)

        # Canlı Sistem Saati
        self.clock_label = QLabel("00:00:00", bar)
        self.clock_label.setObjectName("cardCaption")
        _apply_font(self.clock_label, 9, QFont.Weight.DemiBold, mono=True)
        layout.addWidget(self.clock_label, alignment=Qt.AlignmentFlag.AlignVCenter)

        # Güvenlik Skoru Rozeti
        self.score_pill = StatusPill("KORUMA KAPALI", "warning", bar)
        layout.addWidget(self.score_pill, alignment=Qt.AlignmentFlag.AlignVCenter)

        # Daemon Bağlantı Fişi
        self.daemon_pill = StatusPill("Bağlanıyor…", "text_muted", bar)
        layout.addWidget(self.daemon_pill, alignment=Qt.AlignmentFlag.AlignVCenter)
        return bar

    def _tick_clock(self) -> None:
        """Üst bardaki canlı saati günceller."""
        if hasattr(self, "clock_label"):
            self.clock_label.setText(time.strftime("%H:%M:%S"))

    def _build_banner_holder(self) -> QWidget:
        """Uyarı şeridini bar ile içerik arasına yerleştiren kapsayıcıyı kurar."""
        holder = QWidget(self)
        layout = QVBoxLayout(holder)
        layout.setContentsMargins(24, 10, 24, 0)
        layout.setSpacing(0)
        self.banner = NoticeBanner("warning", holder)
        layout.addWidget(self.banner)
        return holder

    # ------------------------------------------------------------------
    # Gösterge paneli (Dashboard)
    # ------------------------------------------------------------------
    def _create_dashboard_page(self) -> QWidget:
        """Ana gösterge paneli sayfasını kaydırılabilir dashboard düzeniyle oluşturur."""
        scroll = QScrollArea(self)
        scroll.setObjectName("dashboardScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        page = QWidget()
        page.setObjectName("dashboardPage")
        scroll.setWidget(page)

        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 16, 24, 20)
        layout.setSpacing(14)

        # 1. Üst Hızlı Durum Şeridi
        self.speed_bar = NetSpeedBar(page)
        layout.addWidget(self.speed_bar)

        # 2. Orta Gövde: Sol (Kalkan & Kontroller) + Sağ (Canlı Akış & KPI Matrisi)
        hero_row = QHBoxLayout()
        hero_row.setSpacing(14)

        # Sol Kart: Siber Kalkan Komuta Alanı
        shield_card = QFrame(page)
        shield_card.setProperty("class", "cardFrame")
        shield_card.setMinimumWidth(330)
        shield_card.setMaximumWidth(390)

        shield_layout = QVBoxLayout(shield_card)
        shield_layout.setContentsMargins(18, 14, 18, 16)
        shield_layout.setSpacing(10)

        shield_header = QLabel("SİBER GÜVENLİK KALKANI", shield_card)
        shield_header.setObjectName("sectionTitle")
        _apply_font(shield_header, 8, QFont.Weight.Bold, letter_spacing=1.1)
        shield_layout.addWidget(shield_header)

        self.status_ring = StatusRingWidget(shield_card)
        self.status_ring.clicked.connect(self._toggle_connection)
        self.status_ring.setToolTip("Kalkanı açmak veya kapatmak için tıklayın  (Ctrl+K)")
        shield_layout.addWidget(self.status_ring, alignment=Qt.AlignmentFlag.AlignCenter)

        # Hızlı Eylem Butonları
        self.btn_connect = QPushButton("KORUMAYI BAŞLAT", shield_card)
        self.btn_connect.setObjectName("primaryButton")
        self.btn_connect.setMinimumHeight(42)
        self.btn_connect.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_connect.setToolTip("Tor, DNSCrypt, güvenlik duvarı ve MAC kalkanını birlikte devreye alır  (Ctrl+K)")
        self.btn_connect.clicked.connect(self._toggle_connection)
        shield_layout.addWidget(self.btn_connect)

        sub_btn_row = QHBoxLayout()
        sub_btn_row.setSpacing(8)

        self.btn_new_circuit = QPushButton("YENİ KİMLİK", shield_card)
        self.btn_new_circuit.setObjectName("ghostButton")
        self.btn_new_circuit.setIcon(make_icon("refresh", 15, "text_primary"))
        self.btn_new_circuit.setIconSize(QSize(15, 15))
        self.btn_new_circuit.setMinimumHeight(36)
        self.btn_new_circuit.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_new_circuit.setToolTip("Tor devresini yeniler ve çıkış düğümünü değiştirir")
        self.btn_new_circuit.clicked.connect(self._renew_circuit)
        sub_btn_row.addWidget(self.btn_new_circuit, stretch=1)

        self.btn_quick_leak = QPushButton("SIZINTI TESTİ", shield_card)
        self.btn_quick_leak.setObjectName("ghostButton")
        self.btn_quick_leak.setIcon(make_icon("leak", 15, "text_primary"))
        self.btn_quick_leak.setIconSize(QSize(15, 15))
        self.btn_quick_leak.setMinimumHeight(36)
        self.btn_quick_leak.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_quick_leak.setToolTip("Sızıntı denetim paneline geçiş yapar")
        self.btn_quick_leak.clicked.connect(lambda: self._switch_page(2, self.btn_nav_leak))
        sub_btn_row.addWidget(self.btn_quick_leak, stretch=1)
        shield_layout.addLayout(sub_btn_row)

        hero_row.addWidget(shield_card)

        # Sağ Kart: Canlı Ağ Analitiği ve KPI Metrikleri
        analytics_card = QFrame(page)
        analytics_card.setProperty("class", "cardFrame")

        analytics_layout = QVBoxLayout(analytics_card)
        analytics_layout.setContentsMargins(16, 14, 16, 14)
        analytics_layout.setSpacing(12)

        # Canlı Ağ Trafiği Grafiği
        self.traffic_chart = LiveTrafficChart(analytics_card)
        analytics_layout.addWidget(self.traffic_chart, stretch=1)

        # KPI Matrisi (4 Metrik Kutusu)
        kpi_label = QLabel("CANLI OPERASYONEL METRİKLER", analytics_card)
        kpi_label.setObjectName("sectionTitle")
        _apply_font(kpi_label, 8, QFont.Weight.Bold, letter_spacing=1.1)
        analytics_layout.addWidget(kpi_label)

        metrics = QGridLayout()
        metrics.setSpacing(10)
        self.tile_tor = MetricTile("TOR ÇIKIŞ", "Bilinmiyor", "text_muted", analytics_card)
        self.tile_dns = MetricTile("DNSCRYPT", "Bilinmiyor", "text_muted", analytics_card)
        self.tile_renewal = MetricTile("SON KİMLİK", "—", "text_muted", analytics_card)
        self.tile_uptime = MetricTile("ÇALIŞMA SÜRESİ", "—", "text_muted", analytics_card)
        metrics.addWidget(self.tile_tor, 0, 0)
        metrics.addWidget(self.tile_dns, 0, 1)
        metrics.addWidget(self.tile_renewal, 1, 0)
        metrics.addWidget(self.tile_uptime, 1, 1)
        analytics_layout.addLayout(metrics)

        hero_row.addWidget(analytics_card, stretch=1)
        layout.addLayout(hero_row, stretch=1)

        # 3. Servis Kartları Bölümü
        services_label = QLabel("GÜVENLİK VE GİZLİLİK SERVİS OMURGASI", page)
        services_label.setObjectName("sectionTitle")
        _apply_font(services_label, 8, QFont.Weight.Bold, letter_spacing=1.1)
        layout.addWidget(services_label)

        self.card_tor = ServiceCardWidget(
            "Tor Ağı",
            "TCP yönlendirme ve şeffaf proxy",
            GLYPH_TOR,
            page,
            icon=SERVICE_ICONS["tor"],
        )
        self.card_tor.set_detail("TransPort: 9040 · SOCKS5: 9050")

        self.card_dns = ServiceCardWidget(
            "DNSCrypt",
            "Şifreli DNS ve DoH kaçak koruması",
            GLYPH_DNS,
            page,
            icon=SERVICE_ICONS["dns"],
        )
        self.card_dns.set_detail("DNS: 5353 · Şifreli çözümleyici")

        self.card_mac = ServiceCardWidget(
            "MAC Kalkanı",
            "Rastgele donanım adresi",
            GLYPH_MAC,
            page,
            icon=SERVICE_ICONS["mac"],
        )
        self.card_mac.set_detail("Arayüz: Sahte OUI maskesi")

        self.card_forensics = ServiceCardWidget(
            "Adli Temizlik",
            "Bellek ve günlük hijyen motoru",
            GLYPH_FORENSICS,
            page,
            icon=SERVICE_ICONS["forensics"],
        )
        self.card_forensics.set_detail("RAM, Swap, Journal, Shell")

        self._service_cards = [self.card_tor, self.card_dns, self.card_mac, self.card_forensics]
        self._services_grid = QGridLayout()
        self._services_grid.setSpacing(12)
        self._services_columns = 4
        for column in range(4):
            self._services_grid.setColumnStretch(column, 1)
        for column, card in enumerate(self._service_cards):
            self._services_grid.addWidget(card, 0, column)
        layout.addLayout(self._services_grid)
        return scroll

    def _relayout_service_cards(self) -> None:
        """Servis kartlarını pencere genişliğine göre 4 veya 2 sütuna yerleştirir.

        Dar pencerelerde dört sütun kart başlıklarını ve rozetleri sıkıştırdığı
        için 2x2 düzene geçilir; metinler hiçbir genişlikte kırpılmaz.
        """
        grid = getattr(self, "_services_grid", None)
        cards = getattr(self, "_service_cards", None)
        if grid is None or not cards:
            return
        columns = 4 if self.width() >= 1240 else 2
        if columns == getattr(self, "_services_columns", 4):
            return
        self._services_columns = columns
        for card in cards:
            grid.removeWidget(card)
        for column in range(4):
            grid.setColumnStretch(column, 0)
        for column in range(columns):
            grid.setColumnStretch(column, 1)
        for index, card in enumerate(cards):
            grid.addWidget(card, index // columns, index % columns)

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._relayout_service_cards()

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
        self._sync_nav_icons()
        if 0 <= index < len(PAGE_META):
            title, subtitle = PAGE_META[index]
            self.app_bar_title.setText(title)
            self.app_bar_subtitle.setText(subtitle)

    def _sync_nav_icons(self) -> None:
        """Gezinme ikonlarını etkin duruma göre renkleriyle yeniden üretir."""
        if not getattr(self, "_nav_buttons", None):
            return
        for position, btn in enumerate(self._nav_buttons):
            token = "accent" if btn.property("active") == "true" else "text_muted"
            name = NAV_ICONS[position] if position < len(NAV_ICONS) else "dashboard"
            btn.setIcon(make_icon(name, 18, token))
            btn.setIconSize(QSize(18, 18))

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
        """Kapatma isteğinde sistem tepsisi tercihine göre küçülür veya kapanır."""
        close_to_tray = self.current_config.get("gui", {}).get("close_to_tray", True)
        if close_to_tray and getattr(self, "tray_icon", None) is not None and self.tray_icon.isVisible():
            self.hide()
            event.ignore()
            return
        event.accept()

    def _on_settings_saved(self, new_config: Optional[Dict[str, Any]] = None) -> None:
        """Ayarlar paneli güncellendiğinde yapılandırmayı diske kalıcı olarak kaydeder."""
        if new_config is not None:
            self.current_config = new_config
        elif hasattr(self, "page_settings") and hasattr(self.page_settings, "get_current_settings"):
            self.current_config = self.page_settings.get_current_settings()
        config_path = getattr(self.page_settings, "config_path", self.config_path)
        safe_save_config(config_path, self.current_config)

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
        self._sync_nav_icons()

    # ------------------------------------------------------------------
    # Daemon erişilebilirliği
    # ------------------------------------------------------------------
    def _set_daemon_state(self, online: bool, detail: str = "", sync_shield: bool = True) -> None:
        """Daemon erişilebilirliğini arayüze yansıtır.

        `sync_shield=False` iken kalkan görünümü (durum halkası, bağlantı
        butonu) DEĞİŞTİRİLMEZ. Bu, bağlanma işlemi sürerken periyodik durum
        yoklamasının animasyonu kesip butonu geri almasını engeller.
        """
        if online:
            self._daemon_online = True
            self.daemon_pill.set_state("Daemon bağlı", "success")
            self.banner.hide_message()
            if sync_shield:
                self._apply_shield_state(self._is_connected)
            return

        self._daemon_online = False
        self.daemon_pill.set_state("Daemon yok", "danger")
        self.score_pill.set_state("GÜVENLİK YOK", "danger")
        self.status_ring.set_status("UNAVAILABLE")
        self.speed_bar.set_state("warning")
        self.speed_bar.update_info("Denetim yapılamıyor", False, detail)
        self.btn_connect.setText("DAEMON ÇALIŞMIYOR")
        self.btn_connect.setEnabled(False)
        self.btn_new_circuit.setEnabled(False)
        self.tile_tor.set_value("Bilinmiyor", "text_muted")
        self.tile_dns.set_value("Bilinmiyor", "text_muted")
        if hasattr(self, "traffic_chart"):
            self.traffic_chart.set_protected(False, "Daemon Bağlantısı Yok")
        self._update_service_cards(False)
        self.banner.show_message(
            "AnonVoid daemon servisine ulaşılamıyor — kalkan denetlenemiyor ve "
            "trafiğiniz korumasız olabilir. Kök terminalde "
            "'sudo systemctl start anonvoid' ile servisi başlatın.",
            token="danger",
        )

    def _poll_daemon_status(self) -> None:
        """Daemon durumunu periyodik olarak sorgular ve arayüzü senkronize eder."""
        if self._poll_in_flight:
            return

        self._poll_in_flight = True
        # İstek gönderilirkenki sürümü sakla. Yanıt geldiğinde yerel bir
        # kalkan işlemi başlamış/bitmişse bu yanıt BAYATTIR ve durum alanları
        # yazılmamalıdır.
        epoch_at_request = self._shield_epoch

        def _still_current() -> bool:
            return epoch_at_request == self._shield_epoch and not self._shield_op_in_progress

        def _on_success(data: Dict[str, Any]) -> None:
            self._poll_in_flight = False
            if _still_current():
                self._is_connected = bool(data.get("network_shield_active", False))
                self._set_daemon_state(True)
            else:
                # Kalkan işlemi sürüyor: yalnızca daemon erişilebilirliğini
                # işaretle, kalkan görünümüne DOKUNMA.
                self._set_daemon_state(True, sync_shield=False)
            self._update_metrics(data)

        def _on_error(err_msg: str) -> None:
            self._poll_in_flight = False
            self._set_daemon_state(False, err_msg)

        AsyncDaemonWorker(
            client=self.client,
            action="status",
            timeout=3.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _begin_shield_op(self) -> None:
        """Kalkan işlemini başlatır; durum yoklamasının araya girmesini engeller."""
        self._shield_op_in_progress = True
        self._shield_epoch += 1
        self._poll_in_flight = False

    def _end_shield_op(self) -> None:
        """Kalkan işlemini bitirir; bu noktadan sonra yoklamalar geçerlidir."""
        self._shield_op_in_progress = False
        self._shield_epoch += 1

    def _apply_shield_state(self, active: bool) -> None:
        """Kalkanın açık/kapalı durumunu tüm görsel bileşenlere yansıtır."""
        self._is_connected = active
        self.status_ring.set_status("CONNECTED" if active else "OFFLINE")
        self.btn_connect.setText("BAĞLANTIYI KES" if active else "KORUMAYI BAŞLAT")
        self.btn_connect.setEnabled(self._daemon_online)
        self.btn_new_circuit.setEnabled(self._daemon_online and active)
        self._update_service_cards(active)

        if hasattr(self, "traffic_chart"):
            self.traffic_chart.set_protected(active)

        if hasattr(self, "score_pill"):
            if active:
                self.score_pill.set_state("%100 KORUMALI", "success")
            else:
                self.score_pill.set_state("KORUMASIZ AĞ", "warning")

        if active:
            self.speed_bar.update_info("Tor devresi kuruldu", True, "Ayrıntı için sızıntı testini çalıştırın")
            self.card_tor.set_detail("TransPort: 9040 (Aktif) · SOCKS5: 9050")
            self.card_dns.set_detail("DNSCrypt: 5353 (Aktif) · Şifreli Tünel")
        else:
            self.speed_bar.update_info("Kalkan kapalı", False, "Dış IP'niz doğrudan ifşa ediliyor")
            self.card_tor.set_detail("TransPort: 9040 · SOCKS5: 9050")
            self.card_dns.set_detail("DNSCrypt: 5353 · DoH Kaçak Koruması")

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
        self._begin_shield_op()
        self.status_ring.set_status("CONNECTING")
        self.btn_connect.setEnabled(False)
        net_cfg = self.page_settings.config_data.get("network", {})

        def _on_success(data: Dict[str, Any]) -> None:
            # Animasyon yalnızca gerçek yanıt geldiğinde sonlandırılır.
            self._end_shield_op()
            mac_results = data.get("mac_randomized", {})
            self._mac_state = "Uygulandı" if mac_results else "Uygulanmadı"
            self.btn_connect.setEnabled(True)

            connected = bool(data.get("connected", False))
            self._apply_shield_state(connected)

            # Daemon, güvenlik nedeniyle kalkanı KURMAYABİLİR (ör. Tor hazır
            # değil). Bu bir "başarı" değildir; kullanıcıya nedeni açıkça
            # gösterilmelidir. Aksi hâlde ekran sadece "koruma kapalı" der ve
            # kullanıcı hiçbir şey olmadığını sanır.
            if not connected:
                reason = data.get("error") or data.get("tor_check", {}).get("reason") or (
                    "Tor doğrulanamadığı için ağ kalkanı kurulmadı."
                )
                self.status_ring.set_status("OFFLINE")
                QMessageBox.warning(
                    self,
                    "Kalkan Kurulamadı",
                    f"Ağ kalkanı başlatılamadı:\n\n{reason}",
                )
                return

            if connected:
                # Otomatik sızıntı testi kontrolü
                gui_cfg = self.current_config.get("gui", {})
                if gui_cfg.get("auto_leak_test", False) or gui_cfg.get("auto_leak_test_on_connect", False):
                    if hasattr(self, "leak_panel") and hasattr(self.leak_panel, "run_leak_test"):
                        self.leak_panel.run_leak_test()
                    elif hasattr(self, "leak_panel") and hasattr(self.leak_panel, "run_test"):
                        self.leak_panel.run_test()

            if getattr(self, "tray_icon", None) is not None:
                self.tray_icon.showMessage(
                    "AnonVoid Kalkanı Açık",
                    "Tüm giden internet trafiğiniz Tor ve şifreli DNSCrypt üzerinden yönlendiriliyor.",
                    QSystemTrayIcon.MessageIcon.Information,
                    3000,
                )

        def _on_error(err_msg: str) -> None:
            self._end_shield_op()
            self.status_ring.set_status("OFFLINE")
            self.btn_connect.setEnabled(self._daemon_online)
            QMessageBox.warning(self, "Bağlantı Hatası", f"Ağ kalkanı başlatılamadı:\n{err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="connect",
            params={"network": net_cfg},
            # Tor ilk açılışta ~50 sn'de bootstrap olabilir; daemon 90 sn'ye
            # kadar bekler. İstemci zaman aşımı bu süreyi kapsamalıdır.
            timeout=130.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _disconnect_network(self) -> None:
        """Ağ kalkanını güvenle devreden çıkarır."""
        self._begin_shield_op()
        self.btn_connect.setEnabled(False)

        def _on_success(data: Dict[str, Any]) -> None:
            self._end_shield_op()
            self.btn_connect.setEnabled(True)
            self._mac_state = "—"
            self._apply_shield_state(False)

        def _on_error(err_msg: str) -> None:
            self._end_shield_op()
            self.btn_connect.setEnabled(True)
            QMessageBox.warning(self, "Kapatma Hatası", f"Ağ kalkanı kapatılamadı:\n{err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="disconnect",
            timeout=15.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _renew_circuit(self) -> None:
        """Tor devresini yenileyerek çıkış düğümünü değiştirir."""
        self.btn_new_circuit.setEnabled(False)

        def _on_success(data: Dict[str, Any]) -> None:
            self.btn_new_circuit.setEnabled(True)
            self.tile_renewal.set_value(time.strftime("%H:%M:%S"), "success")

        def _on_error(err_msg: str) -> None:
            self.btn_new_circuit.setEnabled(True)
            QMessageBox.warning(self, "Kimlik Yenileme Hatası", f"Tor devresi yenilenemedi:\n{err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="renew_identity",
            timeout=10.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    # ------------------------------------------------------------------
    # Panik / Acil durum (Nuke)
    # ------------------------------------------------------------------
    def _trigger_panic(self) -> None:
        """İki aşamalı panik eylemini tetikler."""
        if not self._panic_armed:
            self._panic_armed = True
            self.btn_panic.setText("▲ ONAY İÇİN TEKRAR BAS")
            self.panic_hint.setText("Acil durum hazırlığı devrede (5 sn)")
            self.panic_hint.setVisible(True)
            self._panic_timer.start(5000)
            return

        self._disarm_panic()
        self._execute_panic()

    def _disarm_panic(self) -> None:
        """Panik butonu onayını sıfırlar."""
        self._panic_armed = False
        self.btn_panic.setText("▲ PANİK / NUKE")
        self.panic_hint.setVisible(False)
        if self._panic_timer.isActive():
            self._panic_timer.stop()

    def _execute_panic(self) -> None:
        """Tüm trafiği keser, bağlantıları düşürür ve adli temizlik yapar."""
        self.status_ring.set_status("PANIC")
        self.speed_bar.set_state("danger")
        self.speed_bar.update_info("PANİK MODU DEVREDE", False, "Ağ izole edildi")
        if hasattr(self, "score_pill"):
            self.score_pill.set_state("AĞ BLOKE EDİLDİ", "danger")

        def _on_success(data: Dict[str, Any]) -> None:
            self._is_connected = False
            self.btn_connect.setText("KORUMAYI BAŞLAT")
            self._update_service_cards(False)
            QMessageBox.critical(
                self,
                "Panik Modu Devrede",
                "Tüm ağ arayüzleri düşürüldü, iptables kuralları trafiği engelledi "
                "ve acil durum bellek hijyeni uygulandı.\n\n"
                "Sistemi normale döndürmek için servisi yeniden başlatın.",
            )

        def _on_error(err_msg: str) -> None:
            QMessageBox.warning(self, "Panik Hatası", f"Panik modu uygulanırken hata:\n{err_msg}")

        AsyncDaemonWorker(
            client=self.client,
            action="panic",
            timeout=15.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()
