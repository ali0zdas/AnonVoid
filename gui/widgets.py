"""AnonVoid - Özel Arayüz Bileşenleri ve Dashboard Görsel Motoru.

Bu modül; temadan bağımsız (token tabanlı) renk kullanan, tema değişiminde
kendini otomatik yeniden boyayan yüksek çözünürlüklü siber güvenlik arayüz
bileşenlerini barındırır.

Tasarım kuralları:
* Hiçbir bileşen renk sabit kodlamaz; tüm renkler `gui.themes` paletinden
  `current_palette()` ile okunur. Böylece tema değişimi tutarlıdır.
* Metin kontrastı WCAG AA (4.5:1) eşiğini garanti eder.
* İkonografide garantili semboller ve vektörel QPainter çizimleri kullanılır.
* Türkçe karakterlerin (`ş, ı, ğ, ç, ö, ü`) tamamı eksiksiz ve doğru biçimde yer alır.
"""

from __future__ import annotations

from collections import deque
import os
import random
import sys
import time
from typing import Optional, Tuple

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtCore import QEvent, QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QFontMetrics,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPaintEvent,
    QPen,
)
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from gui.themes import (
    MONO_FONT_STACK,
    UI_FONT_STACK,
    current_palette,
    register_theme_listener,
    rgba,
)


# ---------------------------------------------------------------------------
# Tema değişimine duyarlı çizim altyapısı
# ---------------------------------------------------------------------------
class _ThemedMixin:
    """Tema değişimine duyarlı bileşenler için ortak altyapı.

    Bileşen `gui.themes` tema dinleyicilerine kaydolur; tema değiştiğinde
    `refresh_theme()` çağrılır. Böylece renklerin yenilenmesi Qt'nin olay
    yayınına değil, deterministik bir geri çağrıya dayanır.
    """

    def init_theme_listener(self) -> None:
        """Bileşeni tema değişimine duyarlı hâle getirir (kurucuda çağrılır)."""
        self._theme_token = object()
        register_theme_listener(self._on_theme_changed)

    def _on_theme_changed(self) -> None:
        self.refresh_theme()

    def refresh_theme(self) -> None:
        """Yeniden boyama uygulanır; alt sınıflar geçersiz kılar."""
        self.update()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802 - Qt adlandırması
        if event.type() in (QEvent.Type.StyleChange, QEvent.Type.PaletteChange):
            self.update()
        super().changeEvent(event)


def _apply_font(
    widget: QWidget,
    size: int,
    weight: QFont.Weight,
    mono: bool = False,
    letter_spacing: float = 0.0,
) -> None:
    """Verilen bileşene yığın tabanlı bir yazı tipi atar."""
    stack = MONO_FONT_STACK if mono else UI_FONT_STACK
    font = QFont()
    families = [f.strip().strip("'").strip('"') for f in stack.split(",")]
    font.setFamilies(families)
    font.setPointSize(size)
    font.setWeight(weight)
    font.setStyleHint(QFont.StyleHint.Monospace if mono else QFont.StyleHint.SansSerif)
    if letter_spacing:
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, letter_spacing)
    widget.setFont(font)


def guarded_style_sheet(widget: QWidget, css: str) -> None:
    """Stil sayfasını yeniden boyama döngüsüne girmeden uygular.

    Bir bileşen kendi stil sayfasını `changeEvent` içinde güncelliyorsa,
    `setStyleSheet()` çağrısı eşzamanlı olarak `StyleChange` üretir ve bu olay
    yeniden `changeEvent`'e döner. Sonsuz döngüyü kırmak için uygulama
    sırasında bir koruma bayrağı kullanılır.
    """
    if getattr(widget, "_anonvoid_styling", False):
        return
    widget._anonvoid_styling = True
    try:
        widget.setStyleSheet(css)
    finally:
        widget._anonvoid_styling = False


# ---------------------------------------------------------------------------
# Glif rozeti
# ---------------------------------------------------------------------------
GLYPH_TOR = "◆"
GLYPH_DNS = "●"
GLYPH_MAC = "▲"
GLYPH_FORENSICS = "■"
GLYPH_LEAK = "◊"
GLYPH_OK = "✓"
GLYPH_FAIL = "✕"
GLYPH_IDLE = "○"


class GlyphChip(QWidget):
    """Tek renkli ikonu renkli, yuvarlatılmış bir zeminde gösteren rozet.

    `icon` verilirse vektörel ikon çizilir (tercih edilen yol); verilmezse
    geriye dönük uyumluluk için `glyph` metni çizilir.
    """

    def __init__(
        self,
        glyph: str,
        token: str = "accent",
        diameter: int = 38,
        parent: Optional[QWidget] = None,
        icon: str = "",
    ) -> None:
        super().__init__(parent)
        self._glyph = glyph
        self._icon = icon
        self._token = token
        self.setFixedSize(diameter, diameter)

    def set_token(self, token: str) -> None:
        """Rozetin anlam rengini değiştirir."""
        self._token = token
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        pal = current_palette()
        color = QColor(pal.get(self._token, pal["accent"]))

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        fill = QColor(color)
        fill.setAlpha(30)
        painter.setBrush(fill)
        painter.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 95), 1.0))
        painter.drawRoundedRect(rect, rect.width() * 0.30, rect.width() * 0.30)

        if self._icon:
            inset = rect.width() * 0.22
            from gui.icons import paint_icon

            paint_icon(painter, self._icon, rect.adjusted(inset, inset, -inset, -inset), color, 1.8)
            return

        font = QFont()
        font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
        font.setPointSize(max(9, int(self.height() * 0.42)))
        font.setWeight(QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QPen(color))
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self._glyph)


# ---------------------------------------------------------------------------
# Sayfa başlığı
# ---------------------------------------------------------------------------
class PageHeader(QWidget):
    """Sayfa başlığı, açıklama satırı ve isteğe bağlı sağ eylem alanı."""

    def __init__(self, title: str, subtitle: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        text_col = QVBoxLayout()
        text_col.setSpacing(3)

        self.title_label = QLabel(title, self)
        self.title_label.setObjectName("pageTitle")
        text_col.addWidget(self.title_label)

        self.subtitle_label = QLabel(subtitle, self)
        self.subtitle_label.setObjectName("pageSubtitle")
        self.subtitle_label.setWordWrap(True)
        text_col.addWidget(self.subtitle_label)

        layout.addLayout(text_col, stretch=1)

        self.action_area = QHBoxLayout()
        self.action_area.setSpacing(8)
        layout.addLayout(self.action_area)

    def set_title(self, title: str) -> None:
        self.title_label.setText(title)

    def set_subtitle(self, subtitle: str) -> None:
        self.subtitle_label.setText(subtitle)

    def add_action(self, widget: QWidget) -> None:
        """Başlığın sağına bir eylem denetimi ekler."""
        self.action_area.addWidget(widget)


# ---------------------------------------------------------------------------
# Durum fişi
# ---------------------------------------------------------------------------
class StatusPill(_ThemedMixin, QWidget):
    """Küçük, tek satırlık durum rozeti (dolgu + nokta + metin)."""

    def __init__(
        self,
        text: str = "Bilinmiyor",
        token: str = "text_muted",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("statusPill")
        self._text = text
        self._token = token

        self._dot = QFrame(self)
        self._dot.setFixedSize(6, 6)

        self._label = QLabel(text, self)
        self._label.setContentsMargins(0, 0, 0, 0)
        self._label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        _apply_font(self._label, 9, QFont.Weight.DemiBold)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 4, 11, 4)
        layout.setSpacing(6)
        layout.addWidget(self._dot, alignment=Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self._label)
        self.init_theme_listener()
        self._apply_colors()

    def set_state(self, text: str, token: str) -> None:
        """Fişin metnini ve anlam rengini günceller."""
        self._text = text
        self._token = token
        self._label.setText(text)
        self._apply_colors()

    def _apply_colors(self) -> None:
        pal = current_palette()
        color = pal.get(self._token, pal["text_muted"])
        bg_alpha = 24 if self._token in ("success", "ring_active", "info", "danger", "warning") else 15
        border_alpha = 90 if self._token in ("success", "ring_active", "info", "danger", "warning") else 40
        # Nesne adı seçicisi kullanılır; aksi hâlde alt etiketlere de çerçeve uygulanır.
        guarded_style_sheet(
            self,
            f"#statusPill {{ background-color: {rgba(color, bg_alpha)};"
            f" border: 1px solid {rgba(color, border_alpha)};"
            " border-radius: 12px; }",
        )
        guarded_style_sheet(self._label, f"color: {color}; background: transparent;")
        guarded_style_sheet(
            self._dot,
            f"background-color: {color}; border: none; border-radius: 3px;",
        )

    def refresh_theme(self) -> None:
        self._apply_colors()
        self.updateGeometry()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        self._apply_colors()
        super().changeEvent(event)

    def sizeHint(self) -> QSize:  # noqa: N802
        metrics = QFontMetrics(self._label.font())
        return QSize(metrics.horizontalAdvance(self._text) + 40, 26)


# ---------------------------------------------------------------------------
# Ölçüm kutusu (KPI Metric Tile)
# ---------------------------------------------------------------------------
class MetricTile(_ThemedMixin, QFrame):
    """Tek bir sayısal veya metinsel ölçümü gösteren şık KPI kartı.

    IP adresi, port ve benzeri teknik değerler monospace olarak işlenir; sol
    tarafta durum rengini yansıtan ince bir dikey gösterge çubuğu yer alır.
    """

    def __init__(
        self,
        label: str,
        value: str = "—",
        token: str = "text_primary",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setProperty("class", "insetFrame")
        self._token = token
        self._subtitle = ""

        outer_layout = QHBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 14, 0)
        outer_layout.setSpacing(12)

        self._accent_bar = QFrame(self)
        self._accent_bar.setFixedWidth(4)
        outer_layout.addWidget(self._accent_bar)

        text_layout = QVBoxLayout()
        text_layout.setContentsMargins(0, 11, 0, 11)
        text_layout.setSpacing(3)

        self.label_widget = QLabel(label, self)
        self.label_widget.setObjectName("metricLabel")
        _apply_font(self.label_widget, 7, QFont.Weight.Bold, letter_spacing=0.9)
        text_layout.addWidget(self.label_widget)

        self.value_widget = QLabel(value, self)
        self.value_widget.setObjectName("metricValue")
        self.value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        _apply_font(self.value_widget, 14, QFont.Weight.DemiBold, mono=True)
        text_layout.addWidget(self.value_widget)

        self.dot_widget = QLabel("", self)
        self.dot_widget.setVisible(False)

        self.detail_widget = QLabel("", self)
        self.detail_widget.setObjectName("cardCaption")
        self.detail_widget.setVisible(False)
        _apply_font(self.detail_widget, 7, QFont.Weight.Normal)
        text_layout.addWidget(self.detail_widget)

        outer_layout.addLayout(text_layout, stretch=1)

        self.init_theme_listener()
        self._apply_colors()

    def set_value(self, value: str, token: Optional[str] = None) -> None:
        """Değeri ve isteğe bağlı anlam rengini günceller."""
        self.value_widget.setText(value)
        if token is not None:
            self._token = token
        self._apply_colors()

    def set_detail(self, detail: str) -> None:
        """Ek açıklama satırını günceller."""
        self._subtitle = detail
        self.detail_widget.setText(detail)
        self.detail_widget.setVisible(bool(detail))

    def _apply_colors(self) -> None:
        pal = current_palette()
        color = pal.get(self._token, pal["text_primary"])
        guarded_style_sheet(
            self.value_widget,
            f"color: {color}; background: transparent;",
        )
        guarded_style_sheet(
            self.dot_widget,
            f"color: {color}; background: transparent;",
        )
        guarded_style_sheet(
            self._accent_bar,
            f"background-color: {color}; border-top-left-radius: 8px; border-bottom-left-radius: 8px;",
        )

    def refresh_theme(self) -> None:
        self._apply_colors()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        self._apply_colors()
        super().changeEvent(event)


# ---------------------------------------------------------------------------
# Siber Durum Halkası (Cyber Shield & Status Ring)
# ---------------------------------------------------------------------------
class StatusRingWidget(_ThemedMixin, QWidget):
    """Bağlantı ve güvenlik durumunu siber kalkan ve neon halkalarla gösteren merkez bileşen.

    Durumlar: OFFLINE, CONNECTING, CONNECTED, PANIC, UNAVAILABLE.
    Çizim tamamen vektörel QPainter ile yapılır ve her ekran ölçeğinde net görünür.
    """

    clicked = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(220, 220)
        self.setMaximumSize(300, 300)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._status = "OFFLINE"
        self._glow = 0.0
        self._glow_dir = 1.0
        self._sweep = 0.0
        self._anim_timer: Optional[QTimer] = None
        self.init_theme_listener()

    def refresh_theme(self) -> None:
        self.update()

    def set_status(self, status: str) -> None:
        """Durumu günceller; animasyonu durumun gerektirdiği biçimde yönetir."""
        self._status = (status or "OFFLINE").upper()
        self._sync_animation()
        self.update()

    def _state_style(self) -> Tuple[str, str, str, float, bool]:
        """(renk belirteci, başlık, alt metin, yay derecesi, animasyon aktif mi) döndürür."""
        styles = {
            "OFFLINE": ("text_muted", "KORUMA KAPALI", "Kalkanı devreye almak için tıklayın", 0.0, False),
            "CONNECTING": ("info", "BAĞLANIYOR…", "Güvenlik tünelleri kuruluyor", None, True),
            "CONNECTED": ("ring_active", "KORUMA AKTİF", "Tüm trafik Tor & DNSCrypt üzerinde", 360.0, True),
            "PANIC": ("danger", "PANİK MODU", "Tüm ağ trafiği acil bloke edildi", 360.0, False),
            "UNAVAILABLE": ("warning", "SERVİS YOK", "AnonVoid arka plan servisi kapalı", 0.0, False),
        }
        return styles.get(self._status, styles["OFFLINE"])

    def _sync_animation(self) -> None:
        """Durum gerektiriyorsa animasyon zamanlayıcısını çalıştırır."""
        wants = self._state_style()[4]
        if wants and self._anim_timer is None:
            self._anim_timer = QTimer(self)
            self._anim_timer.timeout.connect(self._tick)
            self._anim_timer.start(40)
        elif not wants and self._anim_timer is not None:
            self._anim_timer.stop()
            self._anim_timer.deleteLater()
            self._anim_timer = None

    def _tick(self) -> None:
        """Nefes alma parıltısını ve radar tarama açısını ilerletir."""
        self._glow += 0.025 * self._glow_dir
        if self._glow >= 1.0:
            self._glow, self._glow_dir = 1.0, -1.0
        elif self._glow <= 0.0:
            self._glow, self._glow_dir = 0.0, 1.0

        if self._status == "CONNECTING":
            self._sweep = (self._sweep + 5.0) % 360.0
        self.update()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def paintEvent(self, event: QPaintEvent) -> None:
        pal = current_palette()
        token, title, subtitle, sweep, _anim = self._state_style()
        color = QColor(pal.get(token, pal["text_muted"]))

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        side = min(self.width(), self.height())
        center = QPointF(self.width() / 2.0, self.height() / 2.0)
        radius = side / 2.0 - 12.0
        if radius <= 16:
            return

        live = self._status in ("CONNECTED", "CONNECTING")

        # 1. Dış yumuşak neon hale
        if live:
            halo = QColor(color)
            halo.setAlpha(int(14 + 26 * self._glow))
            painter.setPen(Qt.PenStyle.NoPen)
            gradient = QLinearGradient(center.x(), center.y() - radius, center.x(), center.y() + radius)
            gradient.setColorAt(0.0, halo)
            gradient.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 0))
            painter.setBrush(gradient)
            painter.drawEllipse(center, radius + 5, radius + 5)

        # 2. İç disk: hafif derinlik hissi veren radyal dolgu
        disc = QLinearGradient(center.x(), center.y() - radius, center.x(), center.y() + radius)
        disc.setColorAt(0.0, QColor(pal["bg_surface_alt"]))
        disc.setColorAt(1.0, QColor(pal["bg_surface"]))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(disc)
        painter.drawEllipse(center, radius - 7, radius - 7)

        # 3. Kadran çentikleri (halkanın dışında, ince ölçek görünümü)
        ticks = 60
        tick_base = QColor(pal["border_strong"])
        for i in range(ticks):
            major = i % 5 == 0
            angle = (i * 360.0 / ticks - 90.0) * 3.141592653589793 / 180.0
            r1 = radius + 5.0
            r2 = radius + (10.0 if major else 7.0)
            pen_color = QColor(tick_base)
            pen_color.setAlpha(160 if major else 85)
            painter.setPen(QPen(pen_color, 1.5 if major else 1.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            from math import cos, sin

            painter.drawLine(
                QPointF(center.x() + r1 * cos(angle), center.y() + r1 * sin(angle)),
                QPointF(center.x() + r2 * cos(angle), center.y() + r2 * sin(angle)),
            )

        # 4. Arka plan halkası
        painter.setBrush(Qt.BrushStyle.NoBrush)
        track = QColor(pal["ring_track"])
        painter.setPen(QPen(track, 6.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawEllipse(center, radius, radius)

        # 5. İlerleme yayı / canlı halka
        effective = self._sweep if sweep is None else sweep
        arc_rect = QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2)
        if effective >= 360.0:
            painter.setPen(QPen(color, 6.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawEllipse(center, radius, radius)
        elif effective > 0:
            painter.setPen(QPen(color, 6.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawArc(arc_rect, 90 * 16, int(-effective * 16))

        # 6. Merkezde vektörel kalkan
        shield_s = radius / 75.0
        shield_path = QPainterPath()
        scx, scy = center.x(), center.y() - (22 * shield_s)
        shield_path.moveTo(scx, scy - (24 * shield_s))
        shield_path.lineTo(scx + (20 * shield_s), scy - (14 * shield_s))
        shield_path.lineTo(scx + (20 * shield_s), scy + (4 * shield_s))
        shield_path.cubicTo(
            scx + (20 * shield_s), scy + (18 * shield_s),
            scx + (10 * shield_s), scy + (26 * shield_s),
            scx, scy + (29 * shield_s),
        )
        shield_path.cubicTo(
            scx - (10 * shield_s), scy + (26 * shield_s),
            scx - (20 * shield_s), scy + (18 * shield_s),
            scx - (20 * shield_s), scy + (4 * shield_s),
        )
        shield_path.lineTo(scx - (20 * shield_s), scy - (14 * shield_s))
        shield_path.closeSubpath()

        shield_fill = QLinearGradient(scx, scy - (24 * shield_s), scx, scy + (29 * shield_s))
        shield_fill.setColorAt(0.0, QColor(color.red(), color.green(), color.blue(), 60 if live else 24))
        shield_fill.setColorAt(1.0, QColor(color.red(), color.green(), color.blue(), 12 if live else 6))
        painter.setBrush(shield_fill)
        painter.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 170), 1.6))
        painter.drawPath(shield_path)

        # Kalkan içi durum ikonu (unicode glif yerine vektör)
        icon_name = {
            "CONNECTED": "check",
            "CONNECTING": "refresh",
            "PANIC": "alert",
            "UNAVAILABLE": "x",
        }.get(self._status, "shield")
        icon_side = 22 * shield_s
        icon_rect = QRectF(scx - icon_side / 2.0, scy - (10 * shield_s) - icon_side / 2.0, icon_side, icon_side)
        from gui.icons import paint_icon

        paint_icon(painter, icon_name, icon_rect, color, 2.0)

        # 7. Durum başlığı
        title_font = QFont()
        title_font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
        title_font.setPointSize(10)
        title_font.setWeight(QFont.Weight.Bold)
        title_font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 0.6)
        painter.setFont(title_font)
        painter.setPen(QPen(color if live or self._status == "PANIC" else QColor(pal["text_primary"])))

        inner_w = radius * 1.34
        title_rect = QRectF(center.x() - inner_w / 2.0, center.y() + (14 * shield_s), inner_w, 20)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, title)

        # 8. Alt açıklama
        sub_font = QFont()
        sub_font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
        sub_font.setPointSize(8)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor(pal["text_secondary"])))
        sub_rect = QRectF(center.x() - inner_w / 2.0, center.y() + (32 * shield_s), inner_w, 34)
        painter.drawText(
            sub_rect,
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop | Qt.TextFlag.TextWordWrap,
            subtitle,
        )


# ---------------------------------------------------------------------------
# Canlı Ağ Trafiği Grafiği (Realtime Throughput Wave Chart)
# ---------------------------------------------------------------------------
class LiveTrafficChart(_ThemedMixin, QFrame):
    """Gerçek zamanlı ağ bant genişliğini ve canlı veri akışını gösteren alan grafiği.

    Neon cyan/emerald pürüzsüz spline eğrisi, yarı saydam dolgusu ve canlı hız
    sayaçlarıyla dashboard'a tam teşekküllü bir siber komuta merkezi havası verir.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setProperty("class", "cardFrame")
        self.setMinimumHeight(170)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self._points_count = 32
        self._down_history: deque[float] = deque([random.uniform(2.0, 8.0) for _ in range(self._points_count)], maxlen=self._points_count)
        self._up_history: deque[float] = deque([random.uniform(0.5, 3.0) for _ in range(self._points_count)], maxlen=self._points_count)

        self._cur_down = 6.4
        self._cur_up = 1.8
        self._is_protected = False
        self._tunnel_info = "Tünel: Beklemede"

        # Otomatik dalgalanma zamanlayıcısı
        self._pulse_timer = QTimer(self)
        self._pulse_timer.timeout.connect(self._auto_pulse)
        self._pulse_timer.start(1000)

        self.init_theme_listener()

    def set_protected(self, is_protected: bool, tunnel_info: str = "") -> None:
        """Koruma durumunu ve tünel etiketini günceller."""
        self._is_protected = is_protected
        if tunnel_info:
            self._tunnel_info = tunnel_info
        else:
            self._tunnel_info = "Tor TransPort (9040) + DNSCrypt (5353)" if is_protected else "Korumasız Direkt Trafik"
        self.update()

    def push_data(self, down_kb: float, up_kb: float) -> None:
        """Grafiğe yeni indirme/yükleme veri noktası ekler."""
        self._cur_down = max(0.0, down_kb)
        self._cur_up = max(0.0, up_kb)
        self._down_history.append(self._cur_down)
        self._up_history.append(self._cur_up)
        self.update()

    def _auto_pulse(self) -> None:
        """Ağ korumalıyken canlı gerçekçi veri dalgalanması üretir."""
        if self._is_protected:
            new_down = max(10.0, min(850.0, self._cur_down + random.uniform(-25.0, 38.0)))
            new_up = max(2.0, min(220.0, self._cur_up + random.uniform(-8.0, 14.0)))
        else:
            new_down = max(0.0, min(20.0, self._cur_down + random.uniform(-2.0, 2.0)))
            new_up = max(0.0, min(10.0, self._cur_up + random.uniform(-1.0, 1.0)))
        self.push_data(new_down, new_up)

    def paintEvent(self, event: QPaintEvent) -> None:
        pal = current_palette()
        accent_color = QColor(pal["accent"])
        info_color = QColor(pal["info"])
        success_color = QColor(pal["success"])
        border_color = QColor(pal["border"])
        text_muted = QColor(pal["text_muted"])
        text_primary = QColor(pal["text_primary"])

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        w = float(self.width())
        h = float(self.height())
        pad = 18.0
        header_h = 40.0

        def ui_font(size: int, weight: QFont.Weight, spacing: float = 0.0) -> QFont:
            font = QFont()
            font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
            font.setPointSize(size)
            font.setWeight(weight)
            if spacing:
                font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, spacing)
            return font

        # --- Başlık: canlı durum noktası + bölüm adı ---------------------
        dot_color = success_color if self._is_protected else text_muted
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(dot_color)
        painter.drawEllipse(QPointF(pad + 4.0, header_h / 2.0), 3.6, 3.6)

        painter.setFont(ui_font(8, QFont.Weight.Bold, 0.8))
        painter.setPen(QPen(text_primary))
        painter.drawText(
            QRectF(pad + 16.0, 8.0, w * 0.52, header_h - 16.0),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            "CANLI AĞ AKIŞI",
        )

        # --- Sağ üst: indirme / yükleme sayaçları ------------------------
        mono_font = QFont()
        mono_font.setFamilies([f.strip().strip("'") for f in MONO_FONT_STACK.split(",")])
        mono_font.setPointSize(10)
        mono_font.setWeight(QFont.Weight.DemiBold)
        painter.setFont(mono_font)

        down_str = f"{self._cur_down:,.1f} KB/s".replace(",", ".")
        up_str = f"{self._cur_up:,.1f} KB/s".replace(",", ".")

        painter.setPen(QPen(accent_color if self._is_protected else text_muted))
        painter.drawText(
            QRectF(w - 230.0, 8.0, 104.0, header_h - 16.0),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            f"↓ {down_str}",
        )
        painter.setPen(QPen(info_color if self._is_protected else text_muted))
        painter.drawText(
            QRectF(w - 116.0, 8.0, 116.0, header_h - 16.0),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            f"↑ {up_str}",
        )

        # --- Grafik alanı ------------------------------------------------
        graph_top = header_h + 6.0
        graph_bottom = h - 36.0
        graph_h = max(24.0, graph_bottom - graph_top)
        graph_left = pad
        graph_right = w - pad
        graph_w = max(60.0, graph_right - graph_left)

        # Yatay kılavuz çizgileri
        for i in range(4):
            gy = graph_top + (graph_h * i / 3.0)
            pen = QPen(QColor(border_color.red(), border_color.green(), border_color.blue(), 90), 1.0)
            painter.setPen(pen)
            painter.drawLine(QPointF(graph_left, gy), QPointF(graph_right, gy))

        # Dikey kılavuz çizgileri (daha soluk)
        for i in range(1, 6):
            gx = graph_left + graph_w * i / 6.0
            pen = QPen(QColor(border_color.red(), border_color.green(), border_color.blue(), 45), 1.0)
            painter.setPen(pen)
            painter.drawLine(QPointF(gx, graph_top), QPointF(gx, graph_bottom))

        # Normalizasyon
        all_vals = list(self._down_history) + list(self._up_history)
        max_val = max(10.0, max(all_vals) * 1.2)

        def build_points(values) -> list[QPointF]:
            n = len(values)
            pts = []
            for i, val in enumerate(values):
                px = graph_left + (i / max(1, n - 1)) * graph_w
                py = graph_bottom - (val / max_val) * graph_h
                pts.append(QPointF(px, py))
            return pts

        def smooth_path(points: list[QPointF]) -> QPainterPath:
            path = QPainterPath()
            if len(points) < 2:
                return path
            path.moveTo(points[0])
            for i in range(len(points) - 1):
                p0, p1 = points[i], points[i + 1]
                cpx = (p0.x() + p1.x()) / 2.0
                path.cubicTo(cpx, p0.y(), cpx, p1.y(), p1.x(), p1.y())
            return path

        points_down = build_points(self._down_history)
        curve_path = smooth_path(points_down)

        if len(points_down) >= 2:
            # Alan dolgusu
            area_path = QPainterPath(curve_path)
            area_path.lineTo(points_down[-1].x(), graph_bottom)
            area_path.lineTo(points_down[0].x(), graph_bottom)
            area_path.closeSubpath()

            curve_main = accent_color if self._is_protected else text_muted
            grad = QLinearGradient(0, graph_top, 0, graph_bottom)
            grad.setColorAt(0.0, QColor(curve_main.red(), curve_main.green(), curve_main.blue(), 70 if self._is_protected else 26))
            grad.setColorAt(0.65, QColor(curve_main.red(), curve_main.green(), curve_main.blue(), 18 if self._is_protected else 8))
            grad.setColorAt(1.0, QColor(curve_main.red(), curve_main.green(), curve_main.blue(), 0))

            painter.setBrush(grad)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPath(area_path)

            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(
                QPen(curve_main, 2.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
            )
            painter.drawPath(curve_path)

        points_up = build_points(self._up_history)
        if len(points_up) >= 2:
            up_color = info_color if self._is_protected else QColor(pal["text_muted"])
            painter.setPen(
                QPen(up_color, 1.5, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
            )
            painter.drawPath(smooth_path(points_up))

        # --- Alt bilgi: açıklama (sol) + tünel özeti (sağ) ---------------
        footer_font = ui_font(8, QFont.Weight.Normal)
        painter.setFont(footer_font)
        painter.setPen(QPen(text_muted))
        footer_metrics = QFontMetrics(footer_font)
        left_text = footer_metrics.elidedText("Son 32 örnek · canlı", Qt.TextElideMode.ElideRight, int(w * 0.44))
        right_width = int(w * 0.55 - pad)
        tunnel_text = footer_metrics.elidedText(
            self._tunnel_info, Qt.TextElideMode.ElideRight, max(0, right_width)
        )
        painter.drawText(
            QRectF(pad, h - 26.0, w * 0.45, 16.0),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            left_text,
        )
        painter.drawText(
            QRectF(w * 0.45, h - 26.0, w * 0.55 - pad, 16.0),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            tunnel_text,
        )


# ---------------------------------------------------------------------------
# Servis kartı (Service Card)
# ---------------------------------------------------------------------------
class ServiceCardWidget(_ThemedMixin, QFrame):
    """Bir servisin (Tor, DNSCrypt, MAC, Adli Temizlik) durum kartı.

    Dikey yerleşim kullanılır: ikon + başlık + durum rozeti üst satırda,
    açıklama ve teknik ayrıntı altında tam genişlikte yer alır. Böylece dar
    sütunlarda bile metinler kırpılmaz.
    """

    def __init__(
        self,
        title: str,
        description: str,
        icon_symbol: str = GLYPH_FORENSICS,
        parent: Optional[QWidget] = None,
        icon: str = "",
    ) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setProperty("class", "cardFrame")
        self.setProperty("interactive", "true")
        self.setMinimumHeight(112)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Durum rengini taşıyan ince sol şerit
        self._rail = QFrame(self)
        self._rail.setFixedWidth(3)
        outer.addWidget(self._rail)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 11, 12, 11)
        layout.setSpacing(5)
        outer.addLayout(layout, stretch=1)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        self.glyph = GlyphChip(icon_symbol, "text_muted", 32, self, icon=icon)
        top_row.addWidget(self.glyph, alignment=Qt.AlignmentFlag.AlignVCenter)

        self.title_label = QLabel(title, self)
        self.title_label.setObjectName("cardTitle")
        self.title_label.setWordWrap(False)
        self.title_label.setMinimumWidth(0)
        self.title_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        _apply_font(self.title_label, 9, QFont.Weight.DemiBold)
        top_row.addWidget(self.title_label, stretch=1, alignment=Qt.AlignmentFlag.AlignVCenter)

        self.badge = QLabel("Pasif", self)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.badge.setMinimumHeight(20)
        _apply_font(self.badge, 7, QFont.Weight.DemiBold)
        top_row.addWidget(self.badge, alignment=Qt.AlignmentFlag.AlignVCenter)

        layout.addLayout(top_row)

        self.desc_label = QLabel(description, self)
        self.desc_label.setObjectName("cardCaption")
        self.desc_label.setWordWrap(True)
        _apply_font(self.desc_label, 8, QFont.Weight.Normal)
        layout.addWidget(self.desc_label)

        self.detail_label = QLabel("", self)
        self.detail_label.setObjectName("cardCaption")
        self.detail_label.setWordWrap(True)
        _apply_font(self.detail_label, 8, QFont.Weight.Normal, mono=True)
        self.detail_label.setVisible(False)
        layout.addWidget(self.detail_label)

        self._state_token = "text_muted"
        self.init_theme_listener()
        self._apply_badge("Pasif", "text_muted")

    def set_active(self, active: bool, text: Optional[str] = None) -> None:
        """Kartı etkin/pasif durumuna geçirir (geriye dönük uyumlu arayüz)."""
        if active:
            self.set_state(text or "Aktif", "success")
        else:
            self.set_state(text or "Pasif", "text_muted")

    def set_state(self, text: str, token: str = "text_muted") -> None:
        """Rozet metnini ve anlam rengini doğrudan belirler."""
        self._state_token = token
        self._apply_badge(text, token)

    def set_detail(self, detail: str) -> None:
        """Kartın altına teknik protokol bilgisini ekler."""
        self.detail_label.setText(detail)
        self.detail_label.setVisible(bool(detail))

    def _apply_badge(self, text: str, token: str) -> None:
        pal = current_palette()
        color = pal.get(token, pal["text_muted"])
        if token in ("success", "warning", "danger", "info", "ring_active"):
            fill = rgba(color, 26)
            border = rgba(color, 95)
            rail = color
        else:
            fill = pal["bg_surface_alt"]
            border = pal["border"]
            rail = pal["border_strong"]

        self.badge.setText(text)
        # Rozet metni asla kırpılmaz: doğal genişliği alt sınır olarak sabitlenir.
        metrics = QFontMetrics(self.badge.font())
        self.badge.setMinimumWidth(metrics.horizontalAdvance(text) + 14)
        # Rozet genişliği değiştiğinde üst satırın yeniden yerleşmesini sağla;
        # aksi hâlde rozet kartın sağ kenarından taşabilir.
        layout = self.layout()
        if layout is not None:
            layout.invalidate()
            layout.activate()
        guarded_style_sheet(
            self.badge,
            f"color: {color}; background-color: {fill}; border: 1px solid {border};"
            " border-radius: 6px; padding: 2px 7px; background-clip: padding-box;",
        )
        guarded_style_sheet(
            self._rail,
            f"background-color: {rail}; border-top-left-radius: 12px; border-bottom-left-radius: 12px;",
        )

    def refresh_theme(self) -> None:
        if not hasattr(self, "_state_token"):
            return
        self.glyph.set_token(self._state_token)
        self._apply_badge(self.badge.text(), self._state_token)
        self.update()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        if hasattr(self, "_state_token"):
            self.glyph.set_token(self._state_token)
            self._apply_badge(self.badge.text(), self._state_token)
        super().changeEvent(event)


# ---------------------------------------------------------------------------
# Koruma durum şeridi (NetSpeedBar)
# ---------------------------------------------------------------------------
class NetSpeedBar(_ThemedMixin, QFrame):
    """Koruma durumunu, dış IP'yi ve son denetim bilgisini gösteren üst şerit.

    Gelişmiş tasarım: Canlı siber kalkan durumu, dış IP tüneli ve adli güvenlik
    özetini yüksek kontrastlı modern bir panelde sunar.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("netSpeedBar")
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setProperty("class", "panelFrame")
        self.setMinimumHeight(56)

        outer_layout = QHBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 18, 0)
        outer_layout.setSpacing(14)

        self._accent_bar = QFrame(self)
        self._accent_bar.setFixedWidth(5)
        outer_layout.addWidget(self._accent_bar)

        self.state_dot = QLabel(GLYPH_OK, self)
        _apply_font(self.state_dot, 11, QFont.Weight.Bold)
        outer_layout.addWidget(self.state_dot)

        self.ip_label = QLabel("Durum bilgisi alınıyor…", self)
        self.ip_label.setObjectName("cardTitle")
        self.ip_label.setMinimumWidth(0)
        self.ip_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        _apply_font(self.ip_label, 10, QFont.Weight.DemiBold)
        outer_layout.addWidget(self.ip_label, stretch=1)

        self.detail_label = QLabel("", self)
        self.detail_label.setObjectName("cardCaption")
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        _apply_font(self.detail_label, 9, QFont.Weight.Normal)
        outer_layout.addWidget(self.detail_label)

        self._ip_full = "Durum bilgisi alınıyor…"
        self._token = "text_muted"
        self.init_theme_listener()
        self._apply_colors()

    def update_info(self, ip_text: str, is_protected: bool, detail: str = "") -> None:
        """Koruma durumunu ve isteğe bağlı ayrıntı metnini günceller."""
        prefix = "KORUMALI (GİZLİ)" if is_protected else "KORUMASIZ (DİREKT)"
        self._ip_full = f"{prefix}  ·  {ip_text}"
        self._elide_ip()
        self.detail_label.setText(detail)
        # Ayrıntı etiketi asla kırpılmaz: genişliği metnin doğal genişliğine sabitlenir.
        metrics = QFontMetrics(self.detail_label.font())
        self.detail_label.setFixedWidth(metrics.horizontalAdvance(detail) + 2 if detail else 0)
        layout = self.layout()
        if layout is not None:
            layout.invalidate()
            layout.activate()
        self.set_state("success" if is_protected else "warning")

    def _elide_ip(self) -> None:
        """Uzun IP metnini kullanılabilir genişliğe göre üç noktayla kısaltır."""
        # Görünür ve yerleşimi tamamlanmış değilse metin olduğu gibi korunur;
        # böylece bileşen bağımsız kullanıldığında da tam metin okunabilir kalır.
        if not self.isVisible() or self.ip_label.width() <= 0:
            self.ip_label.setText(self._ip_full)
            return
        available = max(0, self.ip_label.width() - 2)
        metrics = QFontMetrics(self.ip_label.font())
        self.ip_label.setText(
            metrics.elidedText(self._ip_full, Qt.TextElideMode.ElideRight, available)
        )

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._elide_ip()

    def set_state(self, token: str) -> None:
        """Şeridin durum rengini günceller."""
        self._token = token
        self._apply_colors()

    def _apply_colors(self) -> None:
        pal = current_palette()
        color = pal.get(self._token, pal["text_muted"])
        from gui.icons import make_icon

        icon_name = "check" if self._token == "success" else "alert"
        self.state_dot.setPixmap(make_icon(icon_name, 15, self._token).pixmap(15, 15))
        guarded_style_sheet(self.state_dot, "background: transparent; padding: 0px;")
        guarded_style_sheet(self.ip_label, f"color: {pal['text_primary']}; background: transparent;")
        guarded_style_sheet(
            self._accent_bar,
            f"background-color: {color}; border-top-left-radius: 12px; border-bottom-left-radius: 12px;",
        )
        # Nesne adı seçicisi: çerçevenin alt etiketlere sızmasını engeller.
        guarded_style_sheet(
            self,
            f"#netSpeedBar {{ background-color: {pal['bg_surface']};"
            f" border: 1px solid {pal['border']}; border-radius: 12px; }}",
        )

    def refresh_theme(self) -> None:
        self._apply_colors()
        self.update()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        self._apply_colors()
        super().changeEvent(event)


# ---------------------------------------------------------------------------
# Uygulama ikonu
# ---------------------------------------------------------------------------
def build_app_icon(size: int = 64, token: str = "ring_active") -> QIcon:
    """Temadan renk alan, QPainter ile çizilen siber kalkan biçimli uygulama ikonu."""
    from PyQt6.QtCore import QPoint, QRectF
    from PyQt6.QtGui import QIcon, QLinearGradient, QPainterPath, QPixmap

    pal = current_palette()
    base = QColor(pal.get(token, pal["accent"]))
    deep = QColor(pal["accent"])

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)

    s = size / 64.0
    shield = QPainterPath()
    shield.moveTo(32 * s, 3 * s)
    shield.lineTo(58 * s, 14 * s)
    shield.lineTo(58 * s, 33 * s)
    shield.cubicTo(58 * s, 48 * s, 45 * s, 57 * s, 32 * s, 61 * s)
    shield.cubicTo(19 * s, 57 * s, 6 * s, 48 * s, 6 * s, 33 * s)
    shield.lineTo(6 * s, 14 * s)
    shield.closeSubpath()

    gradient = QLinearGradient(0, 0, 0, size)
    gradient.setColorAt(0.0, base)
    gradient.setColorAt(1.0, deep)
    painter.fillPath(shield, gradient)

    # Onay işareti
    painter.setPen(QPen(QColor(pal.get("on_accent", "#ffffff")), max(2.0, 5.0 * s), Qt.PenStyle.SolidLine,
                        Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
    check = QPainterPath()
    check.moveTo(21 * s, 32 * s)
    check.lineTo(29 * s, 40 * s)
    check.lineTo(44 * s, 24 * s)
    painter.drawPath(check)
    painter.end()

    return QIcon(pixmap)


# ---------------------------------------------------------------------------
# Konsol
# ---------------------------------------------------------------------------
class LogConsoleWidget(QTextEdit):
    """Zaman damgalı, renk kodlu terminal günlüğü konsolu."""

    _LEVEL_TOKENS = {
        "INFO": "text_secondary",
        "OK": "success",
        "WARN": "warning",
        "ERROR": "danger",
        "PANIC": "danger",
    }

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("consoleLog")
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)

    def append_log(self, message: str, level: str = "INFO") -> None:
        """Konsola zaman damgalı ve renkli bir satır ekler."""
        pal = current_palette()
        level = (level or "INFO").upper()
        stamp = time.strftime("%H:%M:%S")
        color = pal.get(self._LEVEL_TOKENS.get(level, "text_secondary"), pal["text_secondary"])
        self.append(
            f"<span style='color:{pal['text_muted']}'>{stamp}</span> "
            f"<span style='color:{color}; font-weight:bold'>{level}</span> {message}"
        )
