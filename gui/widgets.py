"""AnonVoid - Özel GUI Bileşenleri ve Durum Halkası.

Bu modül; bağlantı durumunu parlayan neon animasyonuyla gösteren StatusRingWidget,
servis durum kartları (ServiceCardWidget), canlı ağ hız çubuğu (NetSpeedBar)
ve terminal konsol bileşenlerini içerir.
"""

from __future__ import annotations

import sys
import time
from typing import Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QLinearGradient,
    QPainter,
    QPaintEvent,
    QPen,
)
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class StatusRingWidget(QWidget):
    """Bağlantı durumunu dairesel neon parlaması ile gösteren durum halkası."""

    clicked = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(220, 220)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._status = "OFFLINE"  # "OFFLINE", "CONNECTING", "CONNECTED", "PANIC"
        self._glow_intensity = 0.0
        self._glow_increasing = True

        # Animasyon zamanlayıcısı (Nefes alma / pulse efekti)
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._animate_pulse)
        self._timer.start(50)

    def set_status(self, status: str) -> None:
        """Durum metnini günceller ve halkayı yeniden çizer."""
        self._status = status.upper()
        self.update()

    def _animate_pulse(self) -> None:
        """Neon parlama efektinin hafifçe nefes almasını sağlar."""
        if self._glow_increasing:
            self._glow_intensity += 0.04
            if self._glow_intensity >= 1.0:
                self._glow_intensity = 1.0
                self._glow_increasing = False
        else:
            self._glow_intensity -= 0.04
            if self._glow_intensity <= 0.0:
                self._glow_intensity = 0.0
                self._glow_increasing = True
        self.update()

    def mousePressEvent(self, event) -> None:
        """Halkaya tıklandığında sinyal üretir."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)

    def paintEvent(self, event: QPaintEvent) -> None:
        """Durum halkasını anti-aliasing ile çizer."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        center = QPointF(rect.width() / 2, rect.height() / 2)
        radius = (min(rect.width(), rect.height()) / 2) - 16

        # Duruma göre renk seçimi
        if self._status == "CONNECTED":
            base_color = QColor(0, 255, 136)       # Neon Yeşil
            text = "KORUMA AKTİF"
            subtext = "Tüm Trafik Tor/DNSCrypt Üzerinde"
        elif self._status == "CONNECTING":
            base_color = QColor(0, 212, 255)       # Neon Mavi
            text = "BAĞLANIYOR..."
            subtext = "Güvenlik Duvarı Yapılandırılıyor"
        elif self._status == "PANIC":
            base_color = QColor(255, 51, 102)      # Neon Kırmızı
            text = "PANİK MODU"
            subtext = "Tüm Ağ Bloke Edildi"
        else:
            base_color = QColor(80, 80, 80)        # Mat Gri
            text = "KORUMA PASİF"
            subtext = "Ağ Kalkanını Açmak İçin Tıklayın"

        # Dış parlama halkası (Glow Effect)
        glow_alpha = int(40 + (self._glow_intensity * 80))
        glow_color = QColor(base_color.red(), base_color.green(), base_color.blue(), glow_alpha)
        glow_pen = QPen(glow_color, 12, Qt.PenStyle.SolidLine)
        painter.setPen(glow_pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(center, radius, radius)

        # Ana dairesel çizgi
        ring_pen = QPen(base_color, 4, Qt.PenStyle.SolidLine)
        painter.setPen(ring_pen)
        painter.drawEllipse(center, radius, radius)

        # İç çember dolgusu
        inner_color = QColor(base_color.red(), base_color.green(), base_color.blue(), 15)
        painter.setBrush(QBrush(inner_color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(center, radius - 4, radius - 4)

        # Durum Metinleri
        painter.setPen(QColor(255, 255, 255))
        font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        painter.setFont(font)
        text_rect = QRectF(center.x() - 90, center.y() - 25, 180, 30)
        painter.drawText(text_rect, Qt.AlignmentFlag.AlignCenter, text)

        painter.setPen(base_color)
        sub_font = QFont("Segoe UI", 8)
        painter.setFont(sub_font)
        sub_rect = QRectF(center.x() - 95, center.y() + 8, 190, 35)
        painter.drawText(sub_rect, Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap, subtext)


class ServiceCardWidget(QFrame):
    """Bireysel servislerin (Tor, DNSCrypt, I2P, Adli Temizleyici) durum kartı."""

    def __init__(
        self,
        title: str,
        description: str,
        icon_symbol: str = "🛡️",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setProperty("class", "cardFrame")
        self.setMinimumHeight(95)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        # İkon Kutusu
        self.icon_label = QLabel(icon_symbol, self)
        self.icon_label.setStyleSheet("font-size: 26px;")
        layout.addWidget(self.icon_label)

        # Başlık ve Açıklama Alanı
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)

        self.title_label = QLabel(title, self)
        self.title_label.setStyleSheet("font-size: 14px; font-weight: bold;")
        text_layout.addWidget(self.title_label)

        self.desc_label = QLabel(description, self)
        self.desc_label.setStyleSheet("font-size: 11px; color: #888888;")
        self.desc_label.setWordWrap(True)
        text_layout.addWidget(self.desc_label)

        layout.addLayout(text_layout, stretch=1)

        # Durum Rozeti (Badge)
        self.badge = QLabel("Pasif", self)
        self.badge.setStyleSheet(
            "background-color: #222222; color: #888888; border-radius: 4px; "
            "padding: 4px 10px; font-size: 11px; font-weight: bold;"
        )
        layout.addWidget(self.badge)

    def set_active(self, active: bool, text: Optional[str] = None) -> None:
        """Kartın durum rozetini aktif/pasif yapar."""
        if active:
            status_text = text or "Aktif"
            self.badge.setText(status_text)
            self.badge.setStyleSheet(
                "background-color: #0d2b1f; color: #00ff88; border: 1px solid #00ff88; "
                "border-radius: 4px; padding: 4px 10px; font-size: 11px; font-weight: bold;"
            )
        else:
            status_text = text or "Pasif"
            self.badge.setText(status_text)
            self.badge.setStyleSheet(
                "background-color: #222222; color: #888888; border-radius: 4px; "
                "padding: 4px 10px; font-size: 11px; font-weight: bold;"
            )


class NetSpeedBar(QFrame):
    """Canlı ağ hızı ve dış IP durum çubuğu."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setProperty("class", "cardFrame")
        self.setMaximumHeight(50)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)

        # Durum İkonu ve IP
        self.ip_label = QLabel("Ağ Durumu: Yerel (Korumasız)", self)
        self.ip_label.setStyleSheet("font-weight: 500; font-size: 12px;")
        layout.addWidget(self.ip_label)

        layout.addStretch()

        # İndirme ve Yükleme Hızları
        self.speed_label = QLabel("⬇ 0.0 KB/s   ⬆ 0.0 KB/s", self)
        self.speed_label.setStyleSheet("font-family: monospace; font-size: 12px; color: #00d4ff;")
        layout.addWidget(self.speed_label)

    def update_info(self, ip_text: str, is_protected: bool) -> None:
        """Ağ ve IP bilgilerini günceller."""
        color = "#00ff88" if is_protected else "#ffaa00"
        status_word = "KORUMALI (Tor)" if is_protected else "KORUMASIZ"
        self.ip_label.setText(f"Ağ: {status_word} | IP: {ip_text}")
        self.ip_label.setStyleSheet(f"font-weight: bold; font-size: 12px; color: {color};")


class LogConsoleWidget(QTextEdit):
    """Renkli ve zaman damgalı terminal günlüğü konsolu."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("consoleLog")
        self.setReadOnly(True)

    def append_log(self, message: str, level: str = "INFO") -> None:
        """Konsola zaman damgalı ve renkli satır ekler."""
        t_str = time.strftime("%H:%M:%S")
        color = "#00ff88"
        if level == "WARN":
            color = "#ffaa00"
        elif level == "ERROR":
            color = "#ff3366"
        elif level == "PANIC":
            color = "#ff0033"

        html_line = f"<span style='color:#666666;'>[{t_str}]</span> <span style='color:{color}; font-weight:bold;'>[{level}]</span> {message}"
        self.append(html_line)
