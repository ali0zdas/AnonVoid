"""AnonVoid - Vektörel ikon motoru.

Unicode semboller yerine QPainter ile çizilen tek renkli çizgi ikonlar kullanılır.
Bu sayede ikonlar her yazı tipinde, her ölçekte ve her temada tutarlı görünür;
emoji/pictograph bağımlılığı oluşmaz.

Tüm ikonlar 24x24 koordinat sisteminde tanımlanır ve verilen dikdörtgene
orantılı biçimde ölçeklenir.
"""

from __future__ import annotations

import os
import sys

sys.dont_write_bytecode = True
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

from typing import Optional

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import (
    QColor,
    QIcon,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)

from gui.themes import current_palette


def _scaled(rect: QRectF, x: float, y: float) -> QPointF:
    """24x24 tasarım koordinatını hedef dikdörtgene ölçekler."""
    return QPointF(rect.left() + rect.width() * x / 24.0, rect.top() + rect.height() * y / 24.0)


def _xy(rect: QRectF, x: float, y: float) -> tuple[float, float]:
    """24x24 tasarım koordinatını (x, y) ikilisi olarak ölçekler."""
    point = _scaled(rect, x, y)
    return point.x(), point.y()


def _pen(color: QColor, width: float) -> QPen:
    pen = QPen(color, width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    return pen


def paint_icon(
    painter: QPainter,
    name: str,
    rect: QRectF,
    color: QColor,
    stroke: float = 1.7,
) -> None:
    """Belirtilen ikonu verilen dikdörtgen içine çizer."""
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    # Çizgi kalınlığı ikon boyutuyla ölçeklenir; küçük ikonlarda okunabilir kalır.
    width = max(1.1, stroke * rect.width() / 24.0 * 1.55)
    painter.setPen(_pen(color, width))

    if name == "dashboard":
        cell = rect.width() * 6.4 / 24.0
        gap = rect.width() * 2.2 / 24.0
        for row in range(2):
            for col in range(2):
                x = rect.left() + col * (cell + gap) + rect.width() * 2.4 / 24.0
                y = rect.top() + row * (cell + gap) + rect.height() * 2.4 / 24.0
                painter.drawRoundedRect(QRectF(x, y, cell, cell), 1.6, 1.6)

    elif name == "forensics":
        # Temizlik/parıltı: büyük ve küçük dört uçlu yıldız.
        big = QPainterPath()
        c = _scaled(rect, 10.0, 10.5)
        r = rect.width() * 6.6 / 24.0
        big.moveTo(c.x(), c.y() - r)
        big.quadTo(c.x(), c.y(), c.x() + r, c.y())
        big.quadTo(c.x(), c.y(), c.x(), c.y() + r)
        big.quadTo(c.x(), c.y(), c.x() - r, c.y())
        big.quadTo(c.x(), c.y(), c.x(), c.y() - r)
        painter.drawPath(big)

        small = QPainterPath()
        c2 = _scaled(rect, 17.4, 17.2)
        r2 = rect.width() * 2.8 / 24.0
        small.moveTo(c2.x(), c2.y() - r2)
        small.quadTo(c2.x(), c2.y(), c2.x() + r2, c2.y())
        small.quadTo(c2.x(), c2.y(), c2.x(), c2.y() + r2)
        small.quadTo(c2.x(), c2.y(), c2.x() - r2, c2.y())
        small.quadTo(c2.x(), c2.y(), c2.x(), c2.y() - r2)
        painter.drawPath(small)

    elif name == "leak":
        # Radar: dış çember, iç yay ve merkez noktası.
        c = _scaled(rect, 12.0, 12.0)
        r = rect.width() * 8.4 / 24.0
        painter.drawEllipse(c, r, r)
        painter.drawEllipse(c, r * 0.58, r * 0.58)
        painter.drawLine(c, _scaled(rect, 18.0, 6.0))
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(c, max(1.0, r * 0.16), max(1.0, r * 0.16))

    elif name == "settings":
        # Kaydırıcılar: üç yatay çizgi ve farklı konumlarda düğmeler.
        for i, (y, knob) in enumerate(((6.5, 9.0), (12.0, 15.0), (17.5, 7.0))):
            painter.setPen(_pen(color, width))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawLine(_scaled(rect, 4.0, y), _scaled(rect, 20.0, y))
            painter.setBrush(QColor(color))
            painter.setPen(_pen(QColor(color), width * 0.75))
            painter.drawEllipse(_scaled(rect, knob, y), rect.width() * 1.55 / 24.0, rect.width() * 1.55 / 24.0)

    elif name == "shield":
        path = QPainterPath()
        path.moveTo(*_xy(rect, 12.0, 3.6))
        path.lineTo(*_xy(rect, 19.4, 6.6))
        path.lineTo(*_xy(rect, 19.4, 11.6))
        path.cubicTo(
            *_xy(rect, 19.4, 16.4),
            *_xy(rect, 16.1, 19.6),
            *_xy(rect, 12.0, 20.9),
        )
        path.cubicTo(
            *_xy(rect, 7.9, 19.6),
            *_xy(rect, 4.6, 16.4),
            *_xy(rect, 4.6, 11.6),
        )
        path.lineTo(*_xy(rect, 4.6, 6.6))
        path.closeSubpath()
        painter.drawPath(path)

    elif name in ("network", "globe"):
        c = _scaled(rect, 12.0, 12.0)
        r = rect.width() * 8.2 / 24.0
        painter.drawEllipse(c, r, r)
        painter.drawEllipse(c, r * 0.46, r)
        painter.drawLine(_scaled(rect, 3.8, 12.0), _scaled(rect, 20.2, 12.0))
        # Enlem eğrisi
        lat = QPainterPath()
        lat.moveTo(*_xy(rect, 4.6, 8.4))
        lat.cubicTo(
            *_xy(rect, 8.4, 6.6),
            *_xy(rect, 15.6, 6.6),
            *_xy(rect, 19.4, 8.4),
        )
        painter.drawPath(lat)

    elif name == "dns":
        # Sunucu yığını: üç yuvarlatılmış gövde ve durum noktaları.
        for i, y in enumerate((4.6, 9.6, 14.6)):
            body = QRectF(
                rect.left() + rect.width() * 3.6 / 24.0,
                rect.top() + rect.height() * y / 24.0,
                rect.width() * 16.8 / 24.0,
                rect.height() * 3.9 / 24.0,
            )
            painter.drawRoundedRect(body, rect.width() * 1.0 / 24.0, rect.width() * 1.0 / 24.0)
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            dot = _scaled(rect, 6.6, y + 1.95)
            painter.drawEllipse(dot, rect.width() * 0.78 / 24.0, rect.width() * 0.78 / 24.0)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(_pen(color, width))

    elif name == "mac":
        # Çip: gövde, iç çekirdek ve yan pinler.
        body = QRectF(
            rect.left() + rect.width() * 6.0 / 24.0,
            rect.top() + rect.height() * 6.0 / 24.0,
            rect.width() * 12.0 / 24.0,
            rect.height() * 12.0 / 24.0,
        )
        painter.drawRoundedRect(body, rect.width() * 2.0 / 24.0, rect.width() * 2.0 / 24.0)
        painter.drawRoundedRect(
            QRectF(
                rect.left() + rect.width() * 9.6 / 24.0,
                rect.top() + rect.height() * 9.6 / 24.0,
                rect.width() * 4.8 / 24.0,
                rect.height() * 4.8 / 24.0,
            ),
            rect.width() * 1.0 / 24.0,
            rect.width() * 1.0 / 24.0,
        )
        for offset in (8.6, 12.0, 15.4):
            painter.drawLine(_scaled(rect, offset, 3.0), _scaled(rect, offset, 6.0))
            painter.drawLine(_scaled(rect, offset, 18.0), _scaled(rect, offset, 21.0))
            painter.drawLine(_scaled(rect, 3.0, offset), _scaled(rect, 6.0, offset))
            painter.drawLine(_scaled(rect, 18.0, offset), _scaled(rect, 21.0, offset))

    elif name == "refresh":
        c = _scaled(rect, 12.0, 12.0)
        r = rect.width() * 7.4 / 24.0
        arc = QRectF(c.x() - r, c.y() - r, r * 2, r * 2)
        painter.drawArc(arc, 40 * 16, 280 * 16)
        # Ok ucu
        tip = _scaled(rect, 18.6, 5.4)
        painter.drawLine(tip, _scaled(rect, 14.2, 4.6))
        painter.drawLine(tip, _scaled(rect, 18.0, 9.8))

    elif name == "power":
        c = _scaled(rect, 12.0, 12.6)
        r = rect.width() * 7.4 / 24.0
        painter.drawArc(QRectF(c.x() - r, c.y() - r, r * 2, r * 2), -60 * 16, 300 * 16)
        painter.drawLine(_scaled(rect, 12.0, 3.4), _scaled(rect, 12.0, 11.4))

    elif name == "check":
        path = QPainterPath()
        path.moveTo(*_xy(rect, 5.2, 12.4))
        path.lineTo(*_xy(rect, 10.0, 17.2))
        path.lineTo(*_xy(rect, 19.0, 7.4))
        painter.drawPath(path)

    elif name == "x":
        painter.drawLine(_scaled(rect, 6.2, 6.2), _scaled(rect, 17.8, 17.8))
        painter.drawLine(_scaled(rect, 17.8, 6.2), _scaled(rect, 6.2, 17.8))

    elif name == "alert":
        painter.drawLine(_scaled(rect, 12.0, 4.2), _scaled(rect, 12.0, 13.6))
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(_scaled(rect, 12.0, 18.4), rect.width() * 1.15 / 24.0, rect.width() * 1.15 / 24.0)

    elif name == "clock":
        c = _scaled(rect, 12.0, 12.0)
        r = rect.width() * 8.0 / 24.0
        painter.drawEllipse(c, r, r)
        painter.drawLine(c, _scaled(rect, 12.0, 7.4))
        painter.drawLine(c, _scaled(rect, 15.6, 13.6))

    elif name == "arrow-right":
        painter.drawLine(_scaled(rect, 4.8, 12.0), _scaled(rect, 18.4, 12.0))
        painter.drawLine(_scaled(rect, 13.2, 6.8), _scaled(rect, 18.4, 12.0))
        painter.drawLine(_scaled(rect, 13.2, 17.2), _scaled(rect, 18.4, 12.0))

    else:
        # Bilinmeyen ad: nötr bir elmas çizilir (sessiz bozulma yerine görünür iz).
        path = QPainterPath()
        path.moveTo(*_xy(rect, 12.0, 4.4))
        path.lineTo(*_xy(rect, 19.6, 12.0))
        path.lineTo(*_xy(rect, 12.0, 19.6))
        path.lineTo(*_xy(rect, 4.4, 12.0))
        path.closeSubpath()
        painter.drawPath(path)

    painter.restore()


def icon_pixmap(
    name: str,
    size: int = 20,
    color: Optional[QColor] = None,
    stroke: float = 1.7,
) -> QPixmap:
    """İkonu saydam zeminli bir QPixmap olarak üretir."""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    col = color or QColor(current_palette()["text_primary"])
    pad = size * 0.08
    paint_icon(painter, name, QRectF(pad, pad, size - 2 * pad, size - 2 * pad), col, stroke)
    painter.end()
    return pixmap


def make_icon(name: str, size: int = 20, token: str = "text_primary") -> QIcon:
    """Tema belirtecinden renk alan bir QIcon üretir."""
    pal = current_palette()
    return QIcon(icon_pixmap(name, size, QColor(pal.get(token, pal["text_primary"]))))
