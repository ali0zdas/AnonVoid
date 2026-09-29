"""AnonVoid - Modern Görsel Temalar ve QSS Stil Motoru.

Bu modül; 5 dinamik görsel temayı (OLED, Circuit, Light, Binary, Pixel) ve
tüm PyQt6 arayüz bileşenleri için donanım hızlandırmalı modern QSS stillerini barındırır.
"""

from __future__ import annotations

import sys
from typing import Any, Dict

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True

# 5 Dinamik Temanın Renk Paletleri
THEME_PALETTES: Dict[str, Dict[str, str]] = {
    # 1. OLED: Saf siyah, modern neon camgöbeği ve yeşil
    "oled": {
        "name": "OLED (Saf Siyah)",
        "bg_main": "#000000",
        "bg_sidebar": "#080808",
        "bg_card": "#111111",
        "bg_card_hover": "#1a1a1a",
        "border": "#222222",
        "border_focus": "#00d4ff",
        "text_primary": "#ffffff",
        "text_secondary": "#888888",
        "text_muted": "#555555",
        "accent": "#00d4ff",
        "accent_hover": "#33ddff",
        "success": "#00ff88",
        "warning": "#ffaa00",
        "danger": "#ff3366",
        "danger_hover": "#ff5588",
        "ring_active": "#00ff88",
        "ring_inactive": "#333333",
    },
    # 2. Circuit: PCB zümrüt yeşili ve siber altın
    "circuit": {
        "name": "Circuit (Siber PCB)",
        "bg_main": "#060d0b",
        "bg_sidebar": "#0a1411",
        "bg_card": "#0f1f1a",
        "bg_card_hover": "#162b24",
        "border": "#1a382e",
        "border_focus": "#10b981",
        "text_primary": "#e2f7f0",
        "text_secondary": "#6ee7b7",
        "text_muted": "#3b7a66",
        "accent": "#10b981",
        "accent_hover": "#34d399",
        "success": "#10b981",
        "warning": "#f59e0b",
        "danger": "#f43f5e",
        "danger_hover": "#fb7185",
        "ring_active": "#10b981",
        "ring_inactive": "#1a382e",
    },
    # 3. Light: Minimalist, ferah ve modern açık tema
    "light": {
        "name": "Light (Modern Açık)",
        "bg_main": "#f8fafc",
        "bg_sidebar": "#f1f5f9",
        "bg_card": "#ffffff",
        "bg_card_hover": "#f8fafc",
        "border": "#cbd5e1",
        "border_focus": "#2563eb",
        "text_primary": "#0f172a",
        "text_secondary": "#475569",
        "text_muted": "#94a3b8",
        "accent": "#2563eb",
        "accent_hover": "#3b82f6",
        "success": "#16a34a",
        "warning": "#d97706",
        "danger": "#dc2626",
        "danger_hover": "#ef4444",
        "ring_active": "#16a34a",
        "ring_inactive": "#cbd5e1",
    },
    # 4. Binary: Matrix hacker yeşili terminal
    "binary": {
        "name": "Binary (Terminal Yeşili)",
        "bg_main": "#050805",
        "bg_sidebar": "#091009",
        "bg_card": "#0d170d",
        "bg_card_hover": "#142414",
        "border": "#1c381c",
        "border_focus": "#22c55e",
        "text_primary": "#4ade80",
        "text_secondary": "#22c55e",
        "text_muted": "#15803d",
        "accent": "#22c55e",
        "accent_hover": "#4ade80",
        "success": "#22c55e",
        "warning": "#eab308",
        "danger": "#ef4444",
        "danger_hover": "#f87171",
        "ring_active": "#22c55e",
        "ring_inactive": "#1c381c",
    },
    # 5. Pixel: Synthwave / Cyberpunk neon mor ve pembe
    "pixel": {
        "name": "Pixel (Cyberpunk Synthwave)",
        "bg_main": "#0c0517",
        "bg_sidebar": "#130924",
        "bg_card": "#1d0e36",
        "bg_card_hover": "#29144d",
        "border": "#3b1d6e",
        "border_focus": "#ec4899",
        "text_primary": "#fdf4ff",
        "text_secondary": "#d946ef",
        "text_muted": "#86198f",
        "accent": "#ec4899",
        "accent_hover": "#f472b6",
        "success": "#06b6d4",
        "warning": "#fbbf24",
        "danger": "#f43f5e",
        "danger_hover": "#fb7185",
        "ring_active": "#ec4899",
        "ring_inactive": "#3b1d6e",
    },
}


def get_theme_stylesheet(theme_key: str = "oled") -> str:
    """Seçilen tema için eksiksiz PyQt6 QSS stil sayfasını oluşturur."""
    pal = THEME_PALETTES.get(theme_key.lower(), THEME_PALETTES["oled"])

    return f"""
    /* Genel Pencere ve Zemin */
    QMainWindow, QDialog {{
        background-color: {pal["bg_main"]};
        color: {pal["text_primary"]};
        font-family: 'Segoe UI', 'Ubuntu', 'DejaVu Sans', sans-serif;
        font-size: 13px;
    }}

    QWidget {{
        color: {pal["text_primary"]};
    }}

    /* Kenar Çubuğu (Sidebar) */
    #sidebarFrame {{
        background-color: {pal["bg_sidebar"]};
        border-right: 1px solid {pal["border"]};
    }}

    /* Kartlar (QFrame) */
    .cardFrame {{
        background-color: {pal["bg_card"]};
        border: 1px solid {pal["border"]};
        border-radius: 10px;
        padding: 12px;
    }}
    .cardFrame:hover {{
        border: 1px solid {pal["border_focus"]};
    }}

    /* Butonlar */
    QPushButton {{
        background-color: {pal["bg_card"]};
        color: {pal["text_primary"]};
        border: 1px solid {pal["border"]};
        border-radius: 6px;
        padding: 8px 16px;
        font-weight: 600;
    }}
    QPushButton:hover {{
        background-color: {pal["bg_card_hover"]};
        border-color: {pal["accent"]};
        color: {pal["accent"]};
    }}
    QPushButton:pressed {{
        background-color: {pal["accent"]};
        color: #000000;
    }}
    QPushButton:disabled {{
        background-color: {pal["bg_main"]};
        color: {pal["text_muted"]};
        border-color: {pal["border"]};
    }}

    /* Birincil Aksiyon Butonu */
    QPushButton#primaryButton {{
        background-color: {pal["accent"]};
        color: #000000;
        border: none;
    }}
    QPushButton#primaryButton:hover {{
        background-color: {pal["accent_hover"]};
    }}

    /* Panik / Nuke Butonu */
    QPushButton#panicButton {{
        background-color: {pal["danger"]};
        color: #ffffff;
        border: 1px solid {pal["danger_hover"]};
        border-radius: 8px;
        font-weight: bold;
        padding: 12px 20px;
        font-size: 14px;
        letter-spacing: 1px;
    }}
    QPushButton#panicButton:hover {{
        background-color: {pal["danger_hover"]};
        border-color: #ffffff;
    }}
    QPushButton#panicButton:pressed {{
        background-color: #990022;
    }}

    /* Kenar Çubuğu Navigasyon Butonları */
    QPushButton.navButton {{
        background-color: transparent;
        color: {pal["text_secondary"]};
        border: none;
        border-radius: 6px;
        text-align: left;
        padding: 10px 14px;
        font-size: 13px;
        font-weight: 500;
    }}
    QPushButton.navButton:hover {{
        background-color: {pal["bg_card"]};
        color: {pal["text_primary"]};
    }}
    QPushButton.navButton:checked, QPushButton.navButton[active="true"] {{
        background-color: {pal["bg_card"]};
        color: {pal["accent"]};
        border-left: 3px solid {pal["accent"]};
        font-weight: bold;
    }}

    /* Giriş Kutuları ve Açılır Menüler */
    QLineEdit, QSpinBox, QComboBox {{
        background-color: {pal["bg_card"]};
        color: {pal["text_primary"]};
        border: 1px solid {pal["border"]};
        border-radius: 6px;
        padding: 6px 10px;
    }}
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus {{
        border: 1px solid {pal["border_focus"]};
    }}
    QComboBox QAbstractItemView {{
        background-color: {pal["bg_card"]};
        color: {pal["text_primary"]};
        selection-background-color: {pal["accent"]};
        selection-color: #000000;
        border: 1px solid {pal["border"]};
    }}

    /* Onay Kutuları (CheckBox) */
    QCheckBox {{
        color: {pal["text_primary"]};
        spacing: 8px;
        font-weight: 500;
    }}
    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border: 1px solid {pal["border"]};
        border-radius: 4px;
        background-color: {pal["bg_card"]};
    }}
    QCheckBox::indicator:hover {{
        border-color: {pal["accent"]};
    }}
    QCheckBox::indicator:checked {{
        background-color: {pal["accent"]};
        border-color: {pal["accent"]};
    }}

    /* İlerleme Çubuğu (QProgressBar) */
    QProgressBar {{
        background-color: {pal["bg_card"]};
        border: 1px solid {pal["border"]};
        border-radius: 6px;
        text-align: center;
        color: {pal["text_primary"]};
        font-weight: bold;
        height: 20px;
    }}
    QProgressBar::chunk {{
        background-color: {pal["accent"]};
        border-radius: 5px;
    }}

    /* Konsol ve Metin Günlük Alanı */
    QTextEdit#consoleLog {{
        background-color: {pal["bg_main"]};
        color: {pal["success"]};
        border: 1px solid {pal["border"]};
        border-radius: 8px;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12px;
        padding: 8px;
    }}

    /* Kaydırma Çubukları (QScrollBar) */
    QScrollBar:vertical {{
        background: {pal["bg_main"]};
        width: 8px;
        border-radius: 4px;
    }}
    QScrollBar::handle:vertical {{
        background: {pal["border"]};
        border-radius: 4px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {pal["text_muted"]};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0px;
    }}
    """


def get_theme(theme_key: str = "oled") -> Dict[str, str]:
    """Seçilen temanın renk paletini döndürür."""
    return THEME_PALETTES.get(theme_key.lower(), THEME_PALETTES["oled"])


def get_available_themes() -> Dict[str, str]:
    """Kullanılabilir tema isimlerini ve anahtarlarını döndürür."""
    return {k: v["name"] for k, v in THEME_PALETTES.items()}


def apply_theme_to_app(app: Any, theme_key: str = "oled") -> None:
    """Belirtilen temayı QApplication nesnesine uygular."""
    stylesheet = get_theme_stylesheet(theme_key)
    if hasattr(app, "setStyleSheet"):
        app.setStyleSheet(stylesheet)
