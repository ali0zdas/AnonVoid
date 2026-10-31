"""AnonVoid - Adli Temizlik Paneli (Forensics).

Bu modül; kullanıcının shell geçmişi, sistem günlükleri, önbellekler, bellek,
SSD TRIM ve boş alan sıfırlama modüllerini seçebileceği kart tabanlı seçim
matrisini, adli maruziyet radarını, ilerleme çubuğunu ve canlı günlük konsolunu
barındırır.

Tasarım ilkeleri:
* Hiçbir renk satır içi sabit kodlanmaz; tüm renkler `gui.themes` paletinden
  `current_palette()` ile okunur. Tema değişiminde panel kendini yeniler.
* Modül seçimi düz onay kutuları yerine tam satır tıklanabilir kartlarla
  yapılır; klavye (boşluk/enter) ile de erişilebilir.
* Uzun sürebilecek veya sistemde kısa kesinti yaratabilecek modüller
  seçildiğinde kullanıcı satır içi uyarı şeridiyle bilgilendirilir.
* Türkçe karakterlerin (`ş, ı, ğ, ç, ö, ü`) tamamı eksiksiz kullanılır.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtCore import QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core.daemon_client import AsyncDaemonWorker, DaemonClient
from gui.icons import make_icon
from gui.themes import (
    MONO_FONT_STACK,
    UI_FONT_STACK,
    current_palette,
    register_theme_listener,
    rgba,
)
from gui.widgets import (
    GLYPH_FORENSICS,
    GlyphChip,
    LogConsoleWidget,
    MetricTile,
    _apply_font,
    guarded_style_sheet,
)


# ---------------------------------------------------------------------------
# Adli risk göstergesi (halka)
# ---------------------------------------------------------------------------
class _RiskGauge(QWidget):
    """Adli maruziyet risk skorunu dairesel halka üzerinde gösteren bileşen."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(116, 116)
        self.setAccessibleName("Adli maruziyet risk göstergesi")
        self._score: Optional[int] = None
        self._level = "BEKLİYOR"
        self._token = "text_muted"

    def set_score(self, score: Optional[int], level: str, token: str) -> None:
        """Skoru, seviye etiketini ve anlam rengini günceller."""
        self._score = None if score is None else max(0, min(100, int(score)))
        self._level = level
        self._token = token
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt adlandırması
        pal = current_palette()
        color = QColor(pal.get(self._token, pal["text_muted"]))
        side = min(self.width(), self.height())
        thickness = max(7.0, side * 0.065)
        margin = thickness / 2.0 + 3.0
        rect = QRectF(
            (self.width() - side) / 2.0 + margin,
            (self.height() - side) / 2.0 + margin,
            side - 2.0 * margin,
            side - 2.0 * margin,
        )

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Arka plan halkası
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(
            QPen(QColor(pal["ring_track"]), thickness, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap)
        )
        painter.drawEllipse(rect)

        # Skor yayı (saat yönünün tersine, tepeden başlar)
        if self._score:
            painter.setPen(QPen(color, thickness, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawArc(rect, 90 * 16, -int(round(self._score * 3.6)) * 16)

        # Merkezdeki sayısal skor
        value_font = QFont()
        value_font.setFamilies([f.strip().strip("'") for f in MONO_FONT_STACK.split(",")])
        value_font.setPointSize(21)
        value_font.setWeight(QFont.Weight.Bold)
        painter.setFont(value_font)
        painter.setPen(QPen(color))
        value_text = "—" if self._score is None else str(self._score)
        painter.drawText(
            QRectF(0, self.height() / 2.0 - 31.0, self.width(), 38.0),
            Qt.AlignmentFlag.AlignCenter,
            value_text,
        )

        # Seviye etiketi
        level_font = QFont()
        level_font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
        level_font.setPointSize(7)
        level_font.setWeight(QFont.Weight.Bold)
        level_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.7)
        painter.setFont(level_font)
        painter.setPen(QPen(QColor(pal["text_muted"])))
        painter.drawText(
            QRectF(0, self.height() / 2.0 + 12.0, self.width(), 16.0),
            Qt.AlignmentFlag.AlignCenter,
            self._level.upper(),
        )
        painter.end()


# ---------------------------------------------------------------------------
# Temizlik modülü kartı
# ---------------------------------------------------------------------------
class _ModuleCard(QFrame):
    """Tek bir temizlik modülünü temsil eden, tıklanabilir seçim kartı.

    `QCheckBox` yerine kullanılır; `isChecked()` / `setChecked()` arayüzü
    korunduğu için panelin hedef toplama mantığı değişmeden çalışır.
    """

    toggled = pyqtSignal(bool)

    def __init__(
        self,
        title: str,
        description: str,
        badge: str = "",
        icon: str = "",
        badge_token: str = "text_muted",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("moduleCard")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMinimumHeight(58)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setAccessibleName(f"{title} temizlik modülü")

        self._checked = False
        self._badge_token = badge_token
        self.setToolTip(
            f"{title}\n{description}\n\nSeçmek için kartın üzerine tıklayın veya boşluk tuşuna basın."
        )

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Seçim durumunu taşıyan ince sol şerit
        self._rail = QFrame(self)
        self._rail.setFixedWidth(3)
        outer.addWidget(self._rail)

        body = QHBoxLayout()
        body.setContentsMargins(12, 8, 12, 8)
        body.setSpacing(10)
        outer.addLayout(body, stretch=1)

        # Seçim göstergesi
        self._indicator = QLabel(self)
        self._indicator.setFixedSize(18, 18)
        self._indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        body.addWidget(self._indicator, alignment=Qt.AlignmentFlag.AlignVCenter)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        head = QHBoxLayout()
        head.setSpacing(8)

        self._title = QLabel(title, self)
        self._title.setObjectName("cardTitle")
        self._title.setWordWrap(True)
        _apply_font(self._title, 9, QFont.Weight.DemiBold)
        head.addWidget(self._title, stretch=1)

        self._badge: Optional[QLabel] = None
        if badge:
            self._badge = QLabel(badge, self)
            self._badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
            _apply_font(self._badge, 7, QFont.Weight.DemiBold)
            head.addWidget(self._badge, alignment=Qt.AlignmentFlag.AlignVCenter)

        text_col.addLayout(head)

        self._desc = QLabel(description, self)
        self._desc.setObjectName("cardCaption")
        self._desc.setWordWrap(True)
        _apply_font(self._desc, 8, QFont.Weight.Normal)
        text_col.addWidget(self._desc)

        body.addLayout(text_col, stretch=1)

        # Modülün görsel kimliği (sağda, seçim durumundan bağımsız)
        self._chip = GlyphChip(GLYPH_FORENSICS, "text_muted", 30, self, icon=icon)
        body.addWidget(self._chip, alignment=Qt.AlignmentFlag.AlignVCenter)

        self._apply_colors()

    # ------------------------------------------------------------------
    def isChecked(self) -> bool:  # noqa: N802 - QCheckBox uyumluluğu
        """Kartın seçili olup olmadığını döndürür."""
        return self._checked

    def setChecked(self, checked: bool) -> None:  # noqa: N802 - QCheckBox uyumluluğu
        """Kartın seçim durumunu değiştirir ve `toggled` sinyalini yayar."""
        checked = bool(checked)
        if checked == self._checked:
            return
        self._checked = checked
        self._apply_colors()
        self.update()
        self.toggled.emit(checked)

    def toggle(self) -> None:
        """Seçim durumunu tersine çevirir."""
        self.setChecked(not self._checked)

    # ------------------------------------------------------------------
    def mousePressEvent(self, event) -> None:  # noqa: N802 - Qt adlandırması
        if event.button() == Qt.MouseButton.LeftButton:
            self.setFocus(Qt.FocusReason.MouseFocusReason)
            self.toggle()
            event.accept()
            return
        super().mousePressEvent(event)

    def keyPressEvent(self, event) -> None:  # noqa: N802 - Qt adlandırması
        if event.key() in (
            Qt.Key.Key_Space,
            Qt.Key.Key_Return,
            Qt.Key.Key_Enter,
        ):
            self.toggle()
            event.accept()
            return
        super().keyPressEvent(event)

    # ------------------------------------------------------------------
    def _apply_colors(self) -> None:
        pal = current_palette()

        if self._checked:
            bg = rgba(pal["accent"], 20)
            hover_bg = rgba(pal["accent"], 32)
            border = rgba(pal["accent"], 130)
            hover_border = pal["accent"]
            rail = pal["accent"]
            indicator_bg = pal["accent"]
            indicator_border = pal["accent"]
        else:
            bg = pal["bg_surface"]
            hover_bg = pal["bg_surface_alt"]
            border = pal["border"]
            hover_border = pal["border_strong"]
            rail = pal["border_strong"]
            indicator_bg = pal["bg_surface_alt"]
            indicator_border = pal["border_strong"]

        guarded_style_sheet(
            self,
            f"#moduleCard {{ background-color: {bg}; border: 1px solid {border};"
            " border-radius: 10px; }"
            f"#moduleCard:hover {{ background-color: {hover_bg}; border: 1px solid {hover_border}; }}"
            f"#moduleCard:focus {{ border: 1px solid {pal['accent']}; }}",
        )
        guarded_style_sheet(
            self._rail,
            f"background-color: {rail}; border-top-left-radius: 9px;"
            " border-bottom-left-radius: 9px;",
        )
        guarded_style_sheet(
            self._indicator,
            f"background-color: {indicator_bg}; border: 1px solid {indicator_border};"
            " border-radius: 5px;",
        )
        if self._checked:
            self._indicator.setPixmap(make_icon("check", 12, "on_accent").pixmap(12, 12))
        else:
            self._indicator.clear()

        guarded_style_sheet(self._title, f"color: {pal['text_primary']}; background: transparent;")
        guarded_style_sheet(
            self._desc, f"color: {pal['text_muted']}; background: transparent; font-size: 11px;"
        )

        if self._badge is not None:
            badge_color = pal.get(self._badge_token, pal["text_muted"])
            guarded_style_sheet(
                self._badge,
                f"color: {badge_color}; background-color: {rgba(badge_color, 20)};"
                f" border: 1px solid {rgba(badge_color, 70)}; border-radius: 5px;"
                " padding: 1px 6px; font-size: 10px;",
            )

        self._chip.set_token("accent" if self._checked else "text_muted")

    def refresh_theme(self) -> None:
        """Tema değişiminde kart renklerini yeniler."""
        self._apply_colors()
        self.update()


# ---------------------------------------------------------------------------
# Adli temizlik paneli
# ---------------------------------------------------------------------------
class ForensicsPanel(QWidget):
    """Adli iz temizleme seçim matrisi ve ilerleme paneli."""

    cleanup_started = pyqtSignal()
    cleanup_finished = pyqtSignal(dict)

    # (denetim, hedef anahtarı, etiket, açıklama, ikon, rozet, rozet belirteci)
    _MODULES = [
        (
            "chk_shell",
            "clean_shell_history",
            "Shell geçmişi",
            "bash, zsh, python, mysql geçmiş dosyaları",
            "terminal",
            "hızlı",
            "text_muted",
        ),
        (
            "chk_journal",
            "clean_journal_logs",
            "Sistem günlükleri",
            "journald vakumu ve metin günlükleri",
            "list",
            "orta",
            "text_muted",
        ),
        (
            "chk_cache",
            "clean_trash",
            "Önbellek ve MRU",
            "küçük resimler, recently-used, çöp kutusu",
            "trash",
            "hızlı",
            "text_muted",
        ),
        (
            "chk_ram",
            "clean_memory_caches",
            "RAM ve takas",
            "drop_caches, compact_memory, swapoff",
            "mac",
            "kesinti riski",
            "warning",
        ),
        (
            "chk_trim",
            "ssd_trim",
            "SSD TRIM",
            "fstrim ile flash hücre sıfırlama",
            "dns",
            "SSD",
            "text_muted",
        ),
        (
            "chk_pkg",
            "clean_package_cache",
            "Paket önbelleği",
            "APT, Pacman, Flatpak ve Snap önbellekleri",
            "box",
            "hızlı",
            "text_muted",
        ),
        (
            "chk_zero_space",
            "free_space_zeroing",
            "Boş alan",
            "kullanılmayan alanın üzerine yazma",
            "forensics",
            "uzun sürer",
            "warning",
        ),
        (
            "chk_swap_zero",
            "clean_swap",
            "Takas alanı",
            "swap alanını urandom ile yeniden yazma",
            "refresh",
            "uzun sürer",
            "warning",
        ),
    ]

    def __init__(self, client: DaemonClient, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.client = client
        self.daemon_client = client

        self._running = False
        self._status_token = "text_muted"
        self._score_token = "text_muted"

        # Kademeli ilerleme çubuğu zamanlayıcısı
        self._progress_steps = [12, 30, 52, 74, 90]
        self._progress_idx = 0
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(700)
        self._progress_timer.timeout.connect(self._step_progress)

        for attr, _key, _label, _desc, _icon, _badge, _token in self._MODULES:
            setattr(self, attr, None)
        self._init_ui()

        # Tema değişiminde kart, uyarı ve durum renklerini tazele
        register_theme_listener(self._on_theme_changed)
        self._refresh_selection_feedback()

    # ------------------------------------------------------------------
    def _init_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        body = QVBoxLayout()
        body.setContentsMargins(24, 20, 24, 22)
        body.setSpacing(14)

        # 1. Adli maruziyet radarı: tam genişlik, tüm temalar için sabit.
        body.addWidget(self._build_radar_card())

        # 2. Alt bölüm: solda yapılandırma (kaydırılabilir), sağda canlı günlük.
        bottom = QHBoxLayout()
        bottom.setSpacing(14)

        scroll = QScrollArea(self)
        scroll.setObjectName("dashboardScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        page = QWidget(scroll)
        page.setObjectName("dashboardPage")
        main_layout = QVBoxLayout(page)
        main_layout.setContentsMargins(0, 0, 6, 0)
        main_layout.setSpacing(10)

        main_layout.addLayout(self._build_module_header())
        main_layout.addWidget(self._build_module_grid())
        main_layout.addWidget(self._build_warning_strip())
        main_layout.addLayout(self._build_action_row())
        main_layout.addLayout(self._build_progress_row())
        main_layout.addStretch(1)

        scroll.setWidget(page)
        bottom.addWidget(scroll, stretch=3)
        bottom.addLayout(self._build_log_column(), stretch=2)
        body.addLayout(bottom, stretch=1)

        root_layout.addLayout(body)

    def _build_log_column(self) -> QVBoxLayout:
        """Sağ sütunda her zaman görünür kalan işlem günlüğünü kurar."""
        column = QVBoxLayout()
        column.setSpacing(8)

        header = QHBoxLayout()
        header.setSpacing(8)

        log_label = QLabel("İŞLEM GÜNLÜĞÜ", self)
        log_label.setObjectName("sectionTitle")
        header.addWidget(log_label)
        header.addStretch(1)

        self.btn_clear_log = QPushButton("Günlüğü Temizle", self)
        self.btn_clear_log.setObjectName("ghostButton")
        self.btn_clear_log.setMinimumHeight(28)
        self.btn_clear_log.setToolTip("Yalnızca ekrandaki işlem günlüğünü temizler.")
        self.btn_clear_log.clicked.connect(self._clear_log)
        header.addWidget(self.btn_clear_log)

        column.addLayout(header)

        self.console = LogConsoleWidget(self)
        self.console.setMinimumWidth(260)
        self.console.setMinimumHeight(160)
        column.addWidget(self.console, stretch=1)
        return column

    def _clear_log(self) -> None:
        """Arayüzdeki işlem günlüğünü temizler."""
        self.console.clear()
        self.console.append_log("İşlem günlüğü temizlendi.", "INFO")

    # ------------------------------------------------------------------
    # Adli maruziyet radarı
    # ------------------------------------------------------------------
    def _build_radar_card(self) -> QFrame:
        radar_card = QFrame(self)
        radar_card.setProperty("class", "cardFrame")

        radar_layout = QHBoxLayout(radar_card)
        radar_layout.setContentsMargins(16, 14, 16, 14)
        radar_layout.setSpacing(18)

        self.gauge = _RiskGauge(radar_card)
        radar_layout.addWidget(self.gauge, alignment=Qt.AlignmentFlag.AlignVCenter)

        info_col = QVBoxLayout()
        info_col.setSpacing(4)

        title_row = QHBoxLayout()
        title_row.setSpacing(10)

        radar_title = QLabel("ADLİ MARUZİYET RADARI", radar_card)
        radar_title.setObjectName("sectionTitle")
        title_row.addWidget(radar_title)
        title_row.addStretch(1)

        self.btn_scan_exposure = QPushButton("İZ ANALİZİ YAP", radar_card)
        self.btn_scan_exposure.setObjectName("ghostButton")
        self.btn_scan_exposure.setMinimumHeight(30)
        self.btn_scan_exposure.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan_exposure.setToolTip(
            "Geçmiş dosyaları ve önbellekleri yerel olarak tarayıp maruziyet skorunu hesaplar."
        )
        self.btn_scan_exposure.clicked.connect(self.scan_exposure)
        title_row.addWidget(self.btn_scan_exposure)

        info_col.addLayout(title_row)

        self.lbl_exposure_score = QLabel("Risk Skoru: Hesaplanmadı", radar_card)
        self.lbl_exposure_score.setObjectName("val_label")
        _apply_font(self.lbl_exposure_score, 10, QFont.Weight.Bold)
        info_col.addWidget(self.lbl_exposure_score)

        self.lbl_exposure_details = QLabel(
            "Komut Geçmişi: —  ·  Önbellek Boyutu: —", radar_card
        )
        self.lbl_exposure_details.setObjectName("cardCaption")
        self.lbl_exposure_details.setWordWrap(True)
        info_col.addWidget(self.lbl_exposure_details)

        tile_row = QHBoxLayout()
        tile_row.setSpacing(8)

        self.tile_history = MetricTile("KOMUT GEÇMİŞİ", "—", "text_muted", radar_card)
        self.tile_cache = MetricTile("ÖNBELLEK", "—", "text_muted", radar_card)
        self.tile_scanned = MetricTile("SON TARAMA", "Bekliyor", "text_muted", radar_card)
        for tile in (self.tile_history, self.tile_cache, self.tile_scanned):
            tile.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
            tile_row.addWidget(tile, stretch=1)

        info_col.addLayout(tile_row)
        info_col.addStretch(1)
        radar_layout.addLayout(info_col, stretch=1)

        self._apply_score_style()
        return radar_card

    # ------------------------------------------------------------------
    # Modül seçim alanı
    # ------------------------------------------------------------------
    def _build_module_header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)

        section = QLabel("TEMİZLİK MODÜLLERİ", self)
        section.setObjectName("sectionTitle")
        row.addWidget(section)

        row.addStretch(1)

        self.lbl_selection = QLabel("", self)
        self.lbl_selection.setObjectName("cardCaption")
        _apply_font(self.lbl_selection, 8, QFont.Weight.DemiBold)
        row.addWidget(self.lbl_selection)

        self.btn_quick = QPushButton("Hızlı", self)
        self.btn_quick.setObjectName("ghostButton")
        self.btn_quick.setToolTip("Yalnızca hızlı tamamlanan dört modülü seçer.")
        self.btn_quick.setMinimumHeight(28)
        self.btn_quick.clicked.connect(self._apply_quick_preset)
        row.addWidget(self.btn_quick)

        self.btn_select_all = QPushButton("Tümü", self)
        self.btn_select_all.setObjectName("ghostButton")
        self.btn_select_all.setToolTip("Tüm temizlik modüllerini seçer.")
        self.btn_select_all.setMinimumHeight(28)
        self.btn_select_all.clicked.connect(self._select_all)
        row.addWidget(self.btn_select_all)

        self.btn_clear_selection = QPushButton("Temizle", self)
        self.btn_clear_selection.setObjectName("ghostButton")
        self.btn_clear_selection.setToolTip("Tüm modül seçimlerini kaldırır.")
        self.btn_clear_selection.setMinimumHeight(28)
        self.btn_clear_selection.clicked.connect(self._clear_selection)
        row.addWidget(self.btn_clear_selection)

        return row

    def _build_module_grid(self) -> QFrame:
        matrix = QFrame(self)
        matrix.setProperty("class", "cardFrame")
        matrix_layout = QGridLayout(matrix)
        matrix_layout.setContentsMargins(8, 8, 8, 8)
        matrix_layout.setHorizontalSpacing(10)
        matrix_layout.setVerticalSpacing(6)

        for index, (attr, _key, label, description, icon, badge, token) in enumerate(
            self._MODULES
        ):
            card = _ModuleCard(label, description, badge, icon, token, matrix)
            card.setChecked(index < 6)
            card.toggled.connect(self._on_module_toggled)
            setattr(self, attr, card)
            matrix_layout.addWidget(card, index // 2, index % 2)

        matrix_layout.setColumnStretch(0, 1)
        matrix_layout.setColumnStretch(1, 1)
        return matrix

    def _build_warning_strip(self) -> QFrame:
        self.warning_strip = QFrame(self)
        self.warning_strip.setObjectName("forensicsWarning")
        warning_layout = QHBoxLayout(self.warning_strip)
        warning_layout.setContentsMargins(12, 8, 12, 8)
        warning_layout.setSpacing(10)

        self.warning_icon = GlyphChip("!", "warning", 24, self.warning_strip, icon="alert")
        warning_layout.addWidget(self.warning_icon, alignment=Qt.AlignmentFlag.AlignTop)

        self.warning_label = QLabel(
            "Seçili modüller disk üzerinde uzun süre çalışabilir ve sistem bir süre "
            "yavaşlayabilir. İşlem sırasında bilgisayarı kapatmayın.",
            self.warning_strip,
        )
        self.warning_label.setWordWrap(True)
        warning_layout.addWidget(self.warning_label, stretch=1)

        self.warning_strip.setVisible(False)
        self._apply_warning_style()
        return self.warning_strip

    def _build_action_row(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)

        self.btn_sanitize_metadata = QPushButton(
            "DOSYA META VERİSİ TEMİZLE (EXIF / PDF / PNG)", self
        )
        self.btn_sanitize_metadata.setObjectName("ghostButton")
        self.btn_sanitize_metadata.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_sanitize_metadata.setToolTip(
            "Seçilen fotoğraf ve belgelerden kamera, konum ve yazar bilgilerini kaldırır."
        )
        self.btn_sanitize_metadata.clicked.connect(self._sanitize_metadata_dialog)
        row.addWidget(self.btn_sanitize_metadata)

        row.addStretch(1)

        self.btn_start = QPushButton("ADLİ TEMİZLİĞİ BAŞLAT", self)
        self.btn_start.setObjectName("primaryButton")
        self.btn_start.setMinimumHeight(40)
        self.btn_start.setMinimumWidth(210)
        self.btn_start.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start.setToolTip("Seçili tüm adli artefaktları root daemon üzerinden temizler.")
        self.btn_start.clicked.connect(self.start_cleanup)
        row.addWidget(self.btn_start)

        return row

    def _build_progress_row(self) -> QVBoxLayout:
        box = QVBoxLayout()
        box.setSpacing(6)

        row = QHBoxLayout()
        row.setSpacing(10)

        self.status_label = QLabel("Hazır: temizlik modüllerini seçip başlatın.", self)
        self.status_label.setObjectName("cardCaption")
        self.status_label.setWordWrap(True)
        row.addWidget(self.status_label, stretch=1)

        self.progress_label = QLabel("%0", self)
        self.progress_label.setObjectName("cardCaption")
        self.progress_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        _apply_font(self.progress_label, 9, QFont.Weight.DemiBold, mono=True)
        row.addWidget(self.progress_label)
        box.addLayout(row)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        self.progress_bar.setMinimumHeight(8)
        box.addWidget(self.progress_bar)
        return box

    # ------------------------------------------------------------------
    # Tema ve seçim geri bildirimi
    # ------------------------------------------------------------------
    def _on_theme_changed(self) -> None:
        """Tema değişiminde kendi çizdiğimiz renkleri yeniler."""
        for card in self._all_checkboxes():
            card.refresh_theme()
        self.warning_icon.update()
        self._apply_score_style()
        self._apply_warning_style()
        self._refresh_selection_feedback()
        self.gauge.update()

    def _apply_score_style(self) -> None:
        pal = current_palette()
        color = pal.get(self._score_token, pal["text_primary"])
        guarded_style_sheet(
            self.lbl_exposure_score,
            f"color: {color}; font-size: 13px; font-weight: bold; background: transparent;",
        )

    def _apply_warning_style(self) -> None:
        pal = current_palette()
        guarded_style_sheet(
            self.warning_strip,
            f"#forensicsWarning {{ background-color: {rgba(pal['warning'], 22)};"
            f" border: 1px solid {rgba(pal['warning'], 80)};"
            f" border-left: 3px solid {pal['warning']}; border-radius: 8px; }}",
        )
        guarded_style_sheet(
            self.warning_label,
            f"color: {pal['text_secondary']}; background: transparent; font-size: 11px;",
        )

    def _on_module_toggled(self, _checked: bool) -> None:
        self._refresh_selection_feedback()

    def _refresh_selection_feedback(self) -> None:
        """Seçim sayacını, uyarı şeridini ve başlat düğmesini günceller."""
        count = sum(1 for card in self._all_checkboxes() if card.isChecked())
        pal = current_palette()

        self.lbl_selection.setText(f"{count} / {len(self._MODULES)} modül seçili")
        guarded_style_sheet(
            self.lbl_selection,
            f"color: {pal['accent'] if count else pal['text_muted']};"
            " font-size: 11px; font-weight: 600; background: transparent;",
        )

        slow_selected = any(
            getattr(self, attr).isChecked() for attr in ("chk_zero_space", "chk_swap_zero")
        )
        self.warning_strip.setVisible(slow_selected)
        self.btn_start.setEnabled(count > 0 and not self._running)

    def _set_busy(self, busy: bool) -> None:
        """Temizlik sürerken seçim ve tarama denetimlerini kilitler."""
        self._running = busy
        for widget in (
            self.btn_quick,
            self.btn_select_all,
            self.btn_clear_selection,
            self.btn_sanitize_metadata,
            self.btn_scan_exposure,
        ):
            widget.setEnabled(not busy)
        self._refresh_selection_feedback()

    # ------------------------------------------------------------------
    def _step_progress(self) -> None:
        """Kademeli ilerleme adımlarını günceller."""
        self._progress_idx += 1
        if self._progress_idx < len(self._progress_steps):
            value = self._progress_steps[self._progress_idx]
            self.progress_bar.setValue(value)
            self.progress_label.setText(f"%{value}")
        else:
            self._progress_timer.stop()

    def _set_progress(self, value: int) -> None:
        """İlerleme çubuğunu ve yüzde etiketini birlikte günceller."""
        value = max(0, min(100, int(value)))
        self.progress_bar.setValue(value)
        self.progress_label.setText(f"%{value}")

    # ------------------------------------------------------------------
    # Maruziyet taraması
    # ------------------------------------------------------------------
    def scan_exposure(self) -> None:
        """Adli maruziyet ve iz analizi taramasını asenkron başlatır."""
        self.btn_scan_exposure.setEnabled(False)
        self.btn_scan_exposure.setText("TARANIYOR…")
        self.lbl_exposure_score.setText("İz analizi taranıyor…")
        self._score_token = "info"
        self._apply_score_style()
        self.console.append_log("Adli maruziyet ve iz analizi başlatıldı…", "INFO")

        def _restore_button() -> None:
            self.btn_scan_exposure.setEnabled(not self._running)
            self.btn_scan_exposure.setText("İZ ANALİZİ YAP")

        def _on_success(data: Dict[str, Any]) -> None:
            _restore_button()
            self._apply_exposure_data(data)

        def _on_error(err_msg: str) -> None:
            # Daemon eylemi desteklemiyorsa veya çevrimdışıysa yerel tarama yap
            self.console.append_log(
                f"Daemon taraması kullanılamadı ({err_msg}); yerel tarama yapılıyor.", "INFO"
            )
            local_data = self._scan_exposure_locally()
            _restore_button()
            self._apply_exposure_data(local_data)

        AsyncDaemonWorker(
            client=self.daemon_client,
            action="scan_exposure",
            timeout=15.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _apply_exposure_data(self, data: Dict[str, Any]) -> None:
        """Tarama sonucunu arayüze ve günlük konsoluna işler."""
        score = int(data.get("risk_score", 0))
        level = str(data.get("risk_level", "DÜŞÜK")).upper()
        history_lines = int(data.get("history_lines", 0))
        cache_mb = float(data.get("cache_mb", 0.0))

        token = "success"
        if score >= 80 or level == "KRİTİK":
            token = "danger"
            level = "KRİTİK"
        elif score >= 55 or level == "YÜKSEK":
            token = "warning"
            level = "YÜKSEK"
        elif score >= 25 or level == "ORTA":
            token = "info"
            level = "ORTA"
        else:
            token = "success"
            level = "DÜŞÜK"

        self._score_token = token
        self._apply_score_style()
        self.lbl_exposure_score.setText(f"Risk Skoru: {score}/100 ({level})")
        self.lbl_exposure_details.setText(
            f"Komut Geçmişi: {history_lines:,} satır  ·  Önbellek: {cache_mb:,.1f} MB".replace(
                ",", "."
            )
        )
        self.gauge.set_score(score, level, token)

        # Ölçüm kutuları: eşikler skorla aynı mantığı izler.
        history_token = "success" if history_lines < 300 else ("warning" if history_lines < 1000 else "danger")
        cache_token = "success" if cache_mb < 50.0 else ("warning" if cache_mb < 200.0 else "danger")
        self.tile_history.set_value(f"{history_lines:,}".replace(",", "."), history_token)
        self.tile_cache.set_value(f"{cache_mb:,.1f} MB".replace(",", "."), cache_token)
        self.tile_scanned.set_value(time.strftime("%H:%M:%S"), "info")

        self.console.append_log(
            f"İz analizi tamamlandı: Risk Skoru {score}/100 ({level}), "
            f"{history_lines} satır geçmiş, {cache_mb:.1f} MB önbellek.",
            "OK" if score < 50 else "WARN",
        )

    def _scan_exposure_locally(self) -> Dict[str, Any]:
        """Kullanıcı dizinlerindeki adli artefaktları tarar ve risk skorunu hesaplar."""
        home = os.path.expanduser("~")
        history_files = [
            ".bash_history",
            ".zsh_history",
            ".python_history",
            ".mysql_history",
            ".sqlite_history",
            ".sh_history",
        ]
        history_lines = 0
        for hf in history_files:
            hp = os.path.join(home, hf)
            # Sembolik bağlar taranmaz: adli iz toplarken bağ tuzaklarına düşülmez.
            if os.path.islink(hp) or not os.path.isfile(hp):
                continue
            try:
                with open(hp, "r", encoding="utf-8", errors="ignore") as f:
                    history_lines += sum(1 for _ in f)
            except Exception:
                pass

        cache_bytes = 0
        cache_dir = os.environ.get("XDG_CACHE_HOME") or os.path.join(home, ".cache")
        if os.path.isdir(cache_dir) and not os.path.islink(cache_dir):
            try:
                count = 0
                for root, _dirs, files in os.walk(cache_dir):
                    for fn in files:
                        count += 1
                        if count > 1000:
                            break
                        fp = os.path.join(root, fn)
                        try:
                            cache_bytes += os.path.getsize(fp)
                        except OSError:
                            pass
                    if count > 1000:
                        break
            except Exception:
                pass

        cache_mb = cache_bytes / (1024.0 * 1024.0)

        # Risk Skoru Algoritması (0 - 100)
        score = 0
        if history_lines > 1000:
            score += 40
        elif history_lines > 300:
            score += 25
        elif history_lines > 0:
            score += 15

        if cache_mb > 200.0:
            score += 40
        elif cache_mb > 50.0:
            score += 25
        elif cache_mb > 5.0:
            score += 15

        score = min(100, max(0, score + 10 if (history_lines or cache_mb) else 5))

        if score >= 80:
            level = "KRİTİK"
        elif score >= 55:
            level = "YÜKSEK"
        elif score >= 25:
            level = "ORTA"
        else:
            level = "DÜŞÜK"

        return {
            "risk_score": score,
            "risk_level": level,
            "history_lines": history_lines,
            "cache_mb": cache_mb,
        }

    # ------------------------------------------------------------------
    # Meta veri temizliği
    # ------------------------------------------------------------------
    def _sanitize_metadata_dialog(self) -> None:
        """Kullanıcının seçtiği medya ve belge dosyalarındaki meta verileri temizler."""
        file_paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Meta Verisi Temizlenecek Dosyaları Seçin",
            "",
            "Desteklenen Dosyalar (*.jpg *.jpeg *.png *.pdf);;Tüm Dosyalar (*.*)",
        )
        if not file_paths:
            return

        self.console.append_log(
            f"{len(file_paths)} adet dosya meta veri temizliği için seçildi.", "INFO"
        )
        success_count = 0

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            for file_path in file_paths:
                base_name = os.path.basename(file_path)
                ok, msg = self._sanitize_file(file_path)
                if ok:
                    success_count += 1
                    self.console.append_log(f"Meta veri temizlendi: {base_name} — {msg}", "OK")
                else:
                    self.console.append_log(
                        f"Meta veri temizlenemedi ({base_name}): {msg}", "ERROR"
                    )
        finally:
            QApplication.restoreOverrideCursor()

        self.console.append_log(
            f"Meta veri temizleme tamamlandı: {success_count}/{len(file_paths)} "
            "dosya başarıyla arındırıldı.",
            "OK" if success_count == len(file_paths) else "WARN",
        )

    def _sanitize_file(self, file_path: str) -> tuple[bool, str]:
        """Tek bir dosyanın meta verisini güvenle temizler."""
        try:
            from core.forensics.metadata import sanitize_file_metadata

            res = sanitize_file_metadata(file_path)
            if isinstance(res, dict):
                ok = bool(res.get("success", False))
                msg = res.get("error") or (
                    f"Temizlendi ({res.get('tags_or_chunks_removed', 0)} etiket/blok silindi, "
                    f"{res.get('bytes_reduced', 0)} bayt azaldı)."
                )
                return ok, msg
            elif isinstance(res, tuple):
                return res
        except (ImportError, AttributeError):
            pass

        ext = os.path.splitext(file_path)[1].lower()
        try:
            if ext in (".jpg", ".jpeg"):
                from PIL import Image

                with Image.open(file_path) as img:
                    data = list(img.getdata())
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(data)
                    clean_img.save(file_path, "JPEG", quality=95)
                return True, "EXIF ve kamera/konum bilgileri kaldırıldı."
            elif ext == ".png":
                from PIL import Image

                with Image.open(file_path) as img:
                    data = list(img.getdata())
                    clean_img = Image.new(img.mode, img.size)
                    clean_img.putdata(data)
                    clean_img.save(file_path, "PNG")
                return True, "PNG metin blokları ve renk profili temizlendi."
            elif ext == ".pdf":
                try:
                    import pypdf

                    reader = pypdf.PdfReader(file_path)
                    writer = pypdf.PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)
                    writer.add_metadata({})
                    temp_pdf = file_path + ".clean"
                    with open(temp_pdf, "wb") as f_out:
                        writer.write(f_out)
                    os.replace(temp_pdf, file_path)
                    return True, "PDF yazar, başlık ve oluşturucu izleri silindi."
                except Exception as p_err:
                    return False, f"PDF işleme hatası: {p_err}"
            else:
                return False, f"Desteklenmeyen dosya türü: {ext}"
        except Exception as err:
            return False, str(err)

    # ------------------------------------------------------------------
    # Seçim yardımcıları
    # ------------------------------------------------------------------
    def _all_checkboxes(self) -> list[_ModuleCard]:
        return [getattr(self, attr) for attr, _k, _l, _d, _i, _b, _t in self._MODULES]

    def _select_all(self) -> None:
        """Tüm modülleri seçer."""
        for card in self._all_checkboxes():
            card.setChecked(True)
        self._refresh_selection_feedback()

    def _clear_selection(self) -> None:
        """Tüm seçimleri kaldırır."""
        for card in self._all_checkboxes():
            card.setChecked(False)
        self._refresh_selection_feedback()

    def _apply_quick_preset(self) -> None:
        """Yalnızca hızlı tamamlanan ilk dört modülü seçer."""
        for index, card in enumerate(self._all_checkboxes()):
            card.setChecked(index < 4)
        self._refresh_selection_feedback()

    def get_selected_targets(self) -> Dict[str, bool]:
        """Kullanıcının seçtiği modülleri hedef sözlüğü olarak döndürür."""
        selected = {
            key: getattr(self, attr).isChecked()
            for attr, key, _l, _d, _i, _b, _t in self._MODULES
        }
        # Birbiriyle eşleşen alt hedefler, ana modülle aynı seçime bağlıdır.
        selected["clean_text_logs"] = selected["clean_journal_logs"]
        selected["clean_thumbnails"] = selected["clean_trash"]
        selected["clean_mru_cache"] = selected["clean_trash"]
        return selected

    def _set_status(self, text: str, token: str) -> None:
        pal = current_palette()
        self._status_token = token
        self.status_label.setText(text)
        guarded_style_sheet(
            self.status_label,
            f"color: {pal.get(token, pal['text_secondary'])};"
            " font-size: 12px; background: transparent;",
        )

    # ------------------------------------------------------------------
    # Temizlik akışı
    # ------------------------------------------------------------------
    def start_cleanup(self) -> None:
        """Temizlik sürecini arayüzü kilitlemeden asenkron başlatır."""
        targets = self.get_selected_targets()
        if not any(targets.values()):
            self._set_status("En az bir modül seçmelisiniz.", "warning")
            return
        if self._running:
            return

        selected_count = sum(1 for card in self._all_checkboxes() if card.isChecked())
        self._set_busy(True)
        self._progress_idx = 0
        self._set_progress(self._progress_steps[0])
        self._progress_timer.start()
        self._set_status("Adli temizlik yürütülüyor…", "info")
        self.console.append_log(
            f"Temizlik talebi root daemon servisine iletildi ({selected_count} hedef).", "INFO"
        )
        self.cleanup_started.emit()

        def _on_success(data: Dict[str, Any]) -> None:
            self._progress_timer.stop()
            self._set_progress(100)
            self._set_status("Adli temizlik başarıyla tamamlandı.", "success")
            self.console.append_log("Tüm seçili adli artefaktlar yok edildi.", "OK")
            self._set_busy(False)
            self.cleanup_finished.emit(data)
            # Temizlik sonrası maruziyet skorunu tazele: kullanıcı farkı görsün.
            QTimer.singleShot(500, self.scan_exposure)

        def _on_error(err_msg: str) -> None:
            self._progress_timer.stop()
            self._set_progress(0)
            self._set_status(f"Hata: {err_msg}", "danger")
            self.console.append_log(f"Temizlik başarısız oldu: {err_msg}", "ERROR")
            self._set_busy(False)

        AsyncDaemonWorker(
            client=self.client,
            action="clean_forensics",
            params={"targets": targets},
            timeout=120.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()
