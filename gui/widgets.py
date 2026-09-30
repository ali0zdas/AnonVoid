"""AnonVoid - Özel Arayüz Bileşenleri.

Bu modül; temadan bağımsız (token tabanlı) renk kullanan, tema değişiminde
kendini otomatik yeniden boyayan arayüz bileşenlerini barındırır.

Tasarım kuralları:
* Hiçbir bileşen renk sabit kodlamaz; tüm renkler `gui.themes` paletinden
  `current_palette()` ile okunur. Böylece tema değişimi tutarlıdır.
* Metin kontrastı WCAG AA (4.5:1) eşiğini garanti eder.
* İkonografide yalnızca DejaVu Sans'ta garanti olarak bulunan tek renkli geometrik
  glifler kullanılır (■ ● ◆ ▲ ✓ ✕ ○ ◊ ▪ ▶). Emoji glifleri (U+1F300 bloğu) Kali
  kurulumlarında çoğunlukla bulunmaz ve tofu kutusu olarak çizilir; bu yüzden
  arayüzde kullanılmaz.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Optional, Tuple

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtCore import QEvent, QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QFontMetrics, QIcon, QPainter, QPaintEvent, QPen
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


def _apply_font(widget: QWidget, size: int, weight: QFont.Weight, mono: bool = False) -> None:
    """Verilen bileşene yığın tabanlı bir yazı tipi atar."""
    stack = MONO_FONT_STACK if mono else UI_FONT_STACK
    font = QFont()
    font.setFamilies([f.strip().strip("'") for f in stack.split(",")])
    font.setPointSize(size)
    font.setWeight(weight)
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
# DejaVu Sans'ta garanti olarak bulunan tek renkli geometrik glifler.
GLYPH_TOR = "◆"
GLYPH_DNS = "●"
GLYPH_MAC = "▲"
GLYPH_FORENSICS = "■"
GLYPH_LEAK = "◊"
GLYPH_OK = "✓"
GLYPH_FAIL = "✕"
GLYPH_IDLE = "○"


class GlyphChip(QWidget):
    """Tek renkli geometrik glifi renkli, yuvarlatılmış bir zeminde gösteren rozet.

    Emoji yerine vektörel görünümlü, platformdan bağımsız bir ikon alanı sağlar.
    """

    def __init__(
        self,
        glyph: str,
        token: str = "accent",
        diameter: int = 34,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._glyph = glyph
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

        rect = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        fill = QColor(color)
        fill.setAlpha(34)
        painter.setBrush(fill)
        painter.setPen(QPen(QColor(color.red(), color.green(), color.blue(), 90), 1))
        painter.drawRoundedRect(rect, 8, 8)

        font = QFont()
        font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
        font.setPointSize(max(8, int(self.height() * 0.42)))
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
        self._text = text
        self._token = token
        self._label = QLabel(text, self)
        self._label.setContentsMargins(0, 0, 0, 0)
        self._label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        _apply_font(self._label, 8, QFont.Weight.DemiBold)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(self._label)
        self.init_theme_listener()

    def set_state(self, text: str, token: str) -> None:
        """Fişin metnini ve anlam rengini günceller."""
        self._text = text
        self._token = token
        self._label.setText(text)
        self._apply_colors()

    def _apply_colors(self) -> None:
        pal = current_palette()
        color = pal.get(self._token, pal["text_muted"])
        guarded_style_sheet(self._label, f"color: {color}; background: transparent;")

    def refresh_theme(self) -> None:
        self._apply_colors()
        self.updateGeometry()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        self._apply_colors()
        super().changeEvent(event)

    def sizeHint(self) -> QSize:  # noqa: N802
        metrics = QFontMetrics(self._label.font())
        return QSize(metrics.horizontalAdvance(self._text) + 22, 22)


# ---------------------------------------------------------------------------
# Ölçüm kutusu
# ---------------------------------------------------------------------------
class MetricTile(_ThemedMixin, QFrame):
    """Tek bir sayısal veya metinsel ölçümü gösteren küçük kart.

    IP adresi, port ve benzeri teknik değerler monospace olarak işlenir; bu
    sayıların hizalı ve taranabilir olmasını sağlar.
    """

    def __init__(
        self,
        label: str,
        value: str = "—",
        token: str = "text_primary",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("class", "insetFrame")
        self._token = token

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 11)
        layout.setSpacing(3)

        self.label_widget = QLabel(label, self)
        self.label_widget.setObjectName("metricLabel")
        layout.addWidget(self.label_widget)

        self.value_widget = QLabel(value, self)
        self.value_widget.setObjectName("metricValue")
        self.value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(self.value_widget)
        self.init_theme_listener()
        self._apply_colors()

    def set_value(self, value: str, token: Optional[str] = None) -> None:
        """Değeri ve isteğe bağlı anlam rengini günceller."""
        self.value_widget.setText(value)
        if token is not None:
            self._token = token
        self._apply_colors()

    def _apply_colors(self) -> None:
        pal = current_palette()
        guarded_style_sheet(
            self.value_widget,
            f"color: {pal.get(self._token, pal['text_primary'])}; background: transparent;",
        )

    def refresh_theme(self) -> None:
        self._apply_colors()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        self._apply_colors()
        super().changeEvent(event)


# ---------------------------------------------------------------------------
# Durum halkası
# ---------------------------------------------------------------------------
class StatusRingWidget(_ThemedMixin, QWidget):
    """Bağlantı ve servis durumunu çizgisel bir halka ile gösteren bileşen.

    Durumlar: OFFLINE, CONNECTING, CONNECTED, PANIC, UNAVAILABLE.
    Çizim tamamen temadan gelen belirteçlerle yapılır.
    """

    clicked = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setMinimumSize(190, 190)
        self.setMaximumSize(250, 250)
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

    # -- durum ------------------------------------------------------------
    def set_status(self, status: str) -> None:
        """Durumu günceller; animasyonu durumun gerektirdiği biçimde yönetir."""
        self._status = (status or "OFFLINE").upper()
        self._sync_animation()
        self.update()

    def _state_style(self) -> Tuple[str, str, str, float, bool]:
        """(renk belirteci, başlık, alt metin, yay süresi, animasyon) döndürür."""
        styles = {
            "OFFLINE": ("text_muted", "KORUMA KAPALI", "Kalkanı başlatmak için tıklayın", 0.0, False),
            "CONNECTING": ("info", "BAĞLANIYOR", "Güvenlik kuralları yazılıyor", None, True),
            "CONNECTED": ("ring_active", "KORUMA AKTİF", "Tüm trafik Tor ve DNSCrypt üzerinde", 268.0, True),
            "PANIC": ("danger", "PANİK MODU", "Tüm ağ trafiği bloke edildi", 268.0, False),
            "UNAVAILABLE": ("warning", "SERVİS YOK", "AnonVoid daemon çalışmıyor", 0.0, False),
        }
        return styles.get(self._status, styles["OFFLINE"])

    def _sync_animation(self) -> None:
        """Durum gerektiriyorsa animasyon zamanlayıcısını çalıştırır, aksi hâlde durdurur."""
        wants = self._state_style()[4]
        if wants and self._anim_timer is None:
            self._anim_timer = QTimer(self)
            self._anim_timer.timeout.connect(self._tick)
            self._anim_timer.start(48)
        elif not wants and self._anim_timer is not None:
            self._anim_timer.stop()
            self._anim_timer.deleteLater()
            self._anim_timer = None

    def _tick(self) -> None:
        """Nefes alma ve yay animasyonunu ilerletir."""
        self._glow += 0.022 * self._glow_dir
        if self._glow >= 1.0:
            self._glow, self._glow_dir = 1.0, -1.0
        elif self._glow <= 0.0:
            self._glow, self._glow_dir = 0.0, 1.0

        if self._status == "CONNECTING":
            self._sweep = (self._sweep + 4.0) % 360.0
        self.update()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    # -- çizim ------------------------------------------------------------
    def paintEvent(self, event: QPaintEvent) -> None:
        pal = current_palette()
        token, title, subtitle, sweep, _anim = self._state_style()
        color = QColor(pal.get(token, pal["text_muted"]))

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        side = min(self.width(), self.height())
        center = QPointF(self.width() / 2.0, self.height() / 2.0)
        radius = side / 2.0 - 14.0
        if radius <= 10:
            return

        # Dış yumuşak hale (yalnızca canlı durumlarda)
        if self._status in ("CONNECTED", "CONNECTING"):
            halo = QColor(color)
            halo.setAlpha(int(18 + 26 * self._glow))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(halo)
            painter.drawEllipse(center, radius + 5, radius + 5)

        # Arka plan halkası
        painter.setBrush(Qt.BrushStyle.NoBrush)
        track = QColor(pal["ring_track"])
        painter.setPen(QPen(track, 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
        painter.drawEllipse(center, radius, radius)

        # İlerleme yayı (altta boşluk bırakan 270°'lik yay)
        effective = self._sweep if sweep is None else sweep
        if effective > 0:
            arc_color = QColor(color)
            painter.setPen(QPen(arc_color, 9, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            painter.drawArc(
                QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2),
                int(16 * 16),
                int(effective * 16),
            )

        # Merkez metinleri
        font = QFont()
        font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
        font.setPointSize(11)
        font.setWeight(QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QPen(QColor(pal["text_primary"])))

        inner = radius - 12
        title_rect = QRectF(center.x() - inner, center.y() - 24, inner * 2, 22)
        painter.drawText(title_rect, Qt.AlignmentFlag.AlignCenter, title)

        sub_font = QFont()
        sub_font.setFamilies([f.strip().strip("'") for f in UI_FONT_STACK.split(",")])
        sub_font.setPointSize(8)
        painter.setFont(sub_font)
        painter.setPen(QPen(QColor(pal["text_muted"])))
        sub_rect = QRectF(center.x() - inner, center.y() - 2, inner * 2, 34)
        painter.drawText(
            sub_rect,
            Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
            subtitle,
        )


# ---------------------------------------------------------------------------
# Servis kartı
# ---------------------------------------------------------------------------
class ServiceCardWidget(_ThemedMixin, QFrame):
    """Bir servisin (Tor, DNSCrypt, MAC, Adli Temizlik) durum kartı.

    Renkler temadan gelir; durum rozeti `set_active()` veya `set_state()` ile
    güncellenir.
    """

    def __init__(
        self,
        title: str,
        description: str,
        icon_symbol: str = GLYPH_FORENSICS,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("class", "cardFrame")
        self.setProperty("interactive", "true")
        self.setMinimumHeight(86)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        self.glyph = GlyphChip(icon_symbol, "text_muted", 34, self)
        layout.addWidget(self.glyph, alignment=Qt.AlignmentFlag.AlignTop)

        text_col = QVBoxLayout()
        text_col.setSpacing(2)

        self.title_label = QLabel(title, self)
        self.title_label.setObjectName("cardTitle")
        self.title_label.setWordWrap(True)
        text_col.addWidget(self.title_label)

        self.desc_label = QLabel(description, self)
        self.desc_label.setObjectName("cardCaption")
        self.desc_label.setWordWrap(True)
        text_col.addWidget(self.desc_label)

        layout.addLayout(text_col, stretch=1)

        self.badge = QLabel("Pasif", self)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge.setMinimumWidth(74)
        self.badge.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        _apply_font(self.badge, 8, QFont.Weight.DemiBold)
        layout.addWidget(self.badge, alignment=Qt.AlignmentFlag.AlignTop)

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

    def _apply_badge(self, text: str, token: str) -> None:
        pal = current_palette()
        self.badge.setText(text)
        color = pal.get(token, pal["text_muted"])
        if token in ("success", "warning", "danger", "info", "ring_active"):
            fill = rgba(color, 30)
            border = rgba(color, 110)
        else:
            fill = pal["bg_surface_alt"]
            border = pal["border"]
        guarded_style_sheet(
            self.badge,
            f"color: {color}; background-color: {fill}; border: 1px solid {border};"
            " border-radius: 5px; padding: 3px 8px; background-clip: padding-box;",
        )

    def refresh_theme(self) -> None:
        self.glyph.set_token(self._state_token)
        self._apply_badge(self.badge.text(), self._state_token)
        self.update()

    def changeEvent(self, event: QEvent) -> None:  # noqa: N802
        self.glyph.set_token(self._state_token)
        self._apply_badge(self.badge.text(), self._state_token)
        super().changeEvent(event)


# ---------------------------------------------------------------------------
# Koruma durum şeridi
# ---------------------------------------------------------------------------
class NetSpeedBar(_ThemedMixin, QFrame):
    """Koruma durumunu, dış IP'yi ve son denetim bilgisini gösteren üst şerit.

    Adı geçmişte "ağ hız çubuğu" idi; ancak ölçüm yapmadığı için bu gösterge
    kullanıcıya yanlış bilgi veriyordu. Bileşen adı test sözleşmesi gereği
    korunmuştur, ancak içerik artık yalnızca doğrulanabilir durum bilgisini
    gösterir.
    """

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setProperty("class", "panelFrame")
        self.setMinimumHeight(52)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 8, 14, 8)
        layout.setSpacing(12)

        self.state_dot = QLabel(GLYPH_OK, self)
        _apply_font(self.state_dot, 9, QFont.Weight.Bold)
        layout.addWidget(self.state_dot)

        self.ip_label = QLabel("Durum bilgisi alınıyor…", self)
        self.ip_label.setObjectName("cardTitle")
        layout.addWidget(self.ip_label, stretch=1)

        self.detail_label = QLabel("", self)
        self.detail_label.setObjectName("cardCaption")
        self.detail_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.detail_label)

        self._token = "text_muted"
        self.init_theme_listener()
        self._apply_colors()

    def update_info(self, ip_text: str, is_protected: bool, detail: str = "") -> None:
        """Koruma durumunu ve isteğe bağlı ayrıntı metnini günceller.

        `ip_text` beklenen değer gerçek bir dış IP veya "Tor üzerinden" gibi
        kısa bir durum metnidir; IP adresi olmayan bir ağ geçidi adresi
        (örneğin "TransPort Aktif") buraya verilmemelidir.
        """
        self.ip_label.setText(f"{'KORUMALI' if is_protected else 'KORUMASIZ'}  ·  {ip_text}")
        self.detail_label.setText(detail)
        self.set_state("success" if is_protected else "warning")

    def set_state(self, token: str) -> None:
        """Şeridin durum rengini günceller."""
        self._token = token
        self._apply_colors()

    def _apply_colors(self) -> None:
        pal = current_palette()
        color = pal.get(self._token, pal["text_muted"])
        self.state_dot.setText(GLYPH_OK if self._token == "success" else GLYPH_FAIL)
        guarded_style_sheet(self.state_dot, f"color: {color}; background: transparent;")
        guarded_style_sheet(self.ip_label, f"color: {color}; background: transparent;")

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
    """Temadan renk alan, QPainter ile çizilen kalkan biçimli uygulama ikonu.

    QtSvg modülü Kali'de kurulu gelmediği için SVG dosyası render edilemez;
    ikon bu şekilde vektörel olarak çizilir ve her boyutta (tepsi ikonu
    dâhil) net görünür.
    """
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
    painter.setPen(QPen(QColor(pal["on_accent"]), max(2.0, 5.0 * s), Qt.PenStyle.SolidLine,
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
