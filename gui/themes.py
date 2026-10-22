"""AnonVoid - Görsel Tema Motoru ve Semantik Renk Sistemi.

Bu modül; tüm grafik arayüz renklerini tek bir kaynaktan yönetir (tek doğruluk
ilkesi). Arayüz bileşenleri renkleri satır içi (inline) sabit kodlamaz; bunun
yerine `current_palette()` üzerinden semantik belirteçleri (token) okurlar.
Böylece tema değişimi bütün arayüzü tutarlı biçimde günceller.

Tasarım kuralları:
* Metin belirteçleri (`text_primary`, `text_secondary`, `text_muted`) kendi
  yüzeyleri üzerinde en az 4.5:1 (WCAG AA) kontrast oranını garanti eder.
* Durum renkleri (`success`, `warning`, `danger`) yalnızca anlam taşıdığında
  kullanılır; dekoratif amaçla kullanılmaz.
* Vurgu renginin üzerindeki metin `on_accent` belirteciyle ayrılır; dolgu
  metin rengini değiştirmek yerine ayrı bir token kullanılır.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Tipografi yığınları: Hem Windows hem Linux (Kali) için garantili sans-serif ve mono.
UI_FONT_STACK = "'Inter', 'Segoe UI', 'Ubuntu', 'Noto Sans', 'DejaVu Sans', 'Liberation Sans', 'Arial', sans-serif"
MONO_FONT_STACK = "'JetBrains Mono', 'Fira Code', 'Cascadia Mono', 'Consolas', 'DejaVu Sans Mono', 'Noto Sans Mono', 'Courier New', monospace"

_ASSET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "ui")


def _asset_url(name: str) -> str:
    """QSS `url(...)` ifadesi için gömülü arayüz varlığının mutlak yolunu üretir."""
    path = os.path.join(_ASSET_DIR, name).replace("\\", "/")
    return f'"{path}"'


# 5 Dinamik Temanın Semantik Renk Paletleri.
# Her palet aynı belirteç kümesini taşır; eksik belirteç olması durumunda
# `resolve_token()` çağrıda güvenli biçimde varsayılana döner.
THEME_PALETTES: Dict[str, Dict[str, str]] = {
    # 1. OLED: Sakin, profesyonel koyu tema. Saf siyah yerine çok koyu lacivert
    #    kullanılır; saf siyah OLED kaydırmada halation yapabilir ve metin
    #    kenarlarını yıpratır.
    "oled": {
        "name": "OLED (Koyu Profesyonel)",
        "bg_main": "#090b0f",
        "bg_sidebar": "#0c0f14",
        "bg_surface": "#11151b",
        "bg_surface_alt": "#161b23",
        "bg_hover": "#1c222c",
        "border": "#212833",
        "border_strong": "#2f3945",
        "accent": "#4f97ff",
        "accent_hover": "#7ab3ff",
        "on_accent": "#06101c",
        "text_primary": "#eef2f7",
        "text_secondary": "#aab5c3",
        "text_muted": "#7d8998",
        "success": "#35d18b",
        "warning": "#f3b64a",
        "danger": "#ff5f6d",
        "info": "#4f97ff",
        "ring_active": "#35d18b",
        "ring_track": "#212833",
        "shadow": "#000000",
    },
    # 2. Circuit: Derin yeşil-slate PCB hissi.
    "circuit": {
        "name": "Circuit (Derin PCB)",
        "bg_main": "#070c0a",
        "bg_sidebar": "#0a120e",
        "bg_surface": "#0e1813",
        "bg_surface_alt": "#132019",
        "bg_hover": "#17261e",
        "border": "#243a2e",
        "border_strong": "#33513f",
        "accent": "#34d399",
        "accent_hover": "#5ee0ac",
        "on_accent": "#04140e",
        "text_primary": "#e6f5ee",
        "text_secondary": "#a7c9ba",
        "text_muted": "#7fa694",
        "success": "#34d399",
        "warning": "#fbbf24",
        "danger": "#fb7185",
        "info": "#38bdf8",
        "ring_active": "#34d399",
        "ring_track": "#243a2e",
        "shadow": "#000000",
    },
    # 3. Light: Düzeltilmiş açık tema. Metin belirteçleri beyaz zemin üzerinde
    #    AA kontrastını geçer.
    "light": {
        "name": "Light (Modern Açık)",
        "bg_main": "#f4f6f8",
        "bg_sidebar": "#ffffff",
        "bg_surface": "#ffffff",
        "bg_surface_alt": "#f1f5f9",
        "bg_hover": "#e9eef3",
        "border": "#d2dbe4",
        "border_strong": "#b6c3d1",
        "accent": "#1d4ed8",
        "accent_hover": "#2563eb",
        "on_accent": "#ffffff",
        "text_primary": "#0f172a",
        "text_secondary": "#475569",
        "text_muted": "#64748b",
        "success": "#15803d",
        "warning": "#b45309",
        "danger": "#dc2626",
        "info": "#0369a1",
        "ring_active": "#15803d",
        "ring_track": "#d5dee7",
        "shadow": "#94a3b8",
    },
    # 4. Binary: Terminal yeşili. Önceki sürümdeki saf #22c55e metin rengi
    #    koyu zeminde okunamıyordu; metinler artık açık yeşile çekildi.
    "binary": {
        "name": "Binary (Terminal Yeşili)",
        "bg_main": "#050806",
        "bg_sidebar": "#080d09",
        "bg_surface": "#0b120c",
        "bg_surface_alt": "#101811",
        "bg_hover": "#141f17",
        "border": "#223524",
        "border_strong": "#305034",
        "accent": "#4ade80",
        "accent_hover": "#6ee7a0",
        "on_accent": "#04140a",
        "text_primary": "#d6f5e0",
        "text_secondary": "#86c99b",
        "text_muted": "#6b9e7d",
        "success": "#4ade80",
        "warning": "#facc15",
        "danger": "#f87171",
        "info": "#38bdf8",
        "ring_active": "#4ade80",
        "ring_track": "#223524",
        "shadow": "#000000",
    },
    # 5. Pixel: Sentez dalgası. Önceki sürümdeki yüksek doygunluklu palet
    #    amatör bir izlenim bırakıyordu; renkler desatüre edilerek dengelendi.
    "pixel": {
        "name": "Pixel (Synthwave)",
        "bg_main": "#0c0713",
        "bg_sidebar": "#110a1a",
        "bg_surface": "#160e23",
        "bg_surface_alt": "#1d1330",
        "bg_hover": "#24183b",
        "border": "#38235d",
        "border_strong": "#4b3077",
        "accent": "#e879c7",
        "accent_hover": "#f0a1da",
        "on_accent": "#1a0a1c",
        "text_primary": "#f0e6f7",
        "text_secondary": "#c3a9d6",
        "text_muted": "#9c82b0",
        "success": "#4fd1c5",
        "warning": "#fcd34d",
        "danger": "#fb7185",
        "info": "#818cf8",
        "ring_active": "#4fd1c5",
        "ring_track": "#38235d",
        "shadow": "#000000",
    },
}

DEFAULT_THEME = "oled"

# Uygulama genelinde etkin tema. Bileşenler boyut/konum bilgisine ihtiyaç
# duymadan güncel paleti buradan okur; tema değişiminde tek noktadan
# güncellenmesi için `set_active_theme()` çağrılır.
_ACTIVE_THEME: str = DEFAULT_THEME

# Tema değişimini dinleyen bileşen geri çağrıları.
# Bileşenler, stil sayfası uygulandığında Qt'nin StyleChange olayını beklemek
# yerine buraya kaydolur; böylece tema değişimi deterministik olarak ve tek
# noktadan yayılır.
_THEME_LISTENERS: List[Callable[[], None]] = []


def register_theme_listener(callback: Callable[[], None]) -> None:
    """Tema değiştiğinde çağrılacak bir geri çağrı kaydeder."""
    if callback not in _THEME_LISTENERS:
        _THEME_LISTENERS.append(callback)


def unregister_theme_listener(callback: Callable[[], None]) -> None:
    """Kayıtlı bir tema dinleyicisini kaldırır."""
    if callback in _THEME_LISTENERS:
        _THEME_LISTENERS.remove(callback)


def _notify_theme_listeners() -> None:
    """Tüm tema dinleyicilerine yeni paletin geçerli olduğunu bildirir."""
    for callback in list(_THEME_LISTENERS):
        try:
            callback()
        except RuntimeError:
            # Dinleyici ait olduğu C++ nesnesi silinmişse kaydı düşür.
            unregister_theme_listener(callback)


# ---------------------------------------------------------------------------
# Kontrast yardımcıları (WCAG 2.1)
# ---------------------------------------------------------------------------
def _srgb_to_linear(channel: float) -> float:
    """Bir sRGB kanal değerini lineer ışıklığa çevirir (0.0-1.0 aralığında)."""
    if channel <= 0.04045:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def _hex_to_rgb(color: str) -> Tuple[int, int, int]:
    """`#rrggbb` biçimindeki bir rengi RGB üçlüsüne ayrıştırır."""
    value = color.strip().lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def relative_luminance(color: str) -> float:
    """Verilen rengin WCAG göreli parlaklığını hesaplar (0.0-1.0)."""
    r, g, b = _hex_to_rgb(color)
    return (
        0.2126 * _srgb_to_linear(r / 255.0)
        + 0.7152 * _srgb_to_linear(g / 255.0)
        + 0.0722 * _srgb_to_linear(b / 255.0)
    )


def contrast_ratio(foreground: str, background: str) -> float:
    """İki renk arasındaki WCAG kontrast oranını döndürür (1.0-21.0).

    Metin okunabilirliğini doğrulamak ve palet regresyonlarını testlerde
    yakalamak için kullanılır.
    """
    l1 = relative_luminance(foreground)
    l2 = relative_luminance(background)
    lighter, darker = max(l1, l2), min(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)


def rgba(hex_color: str, alpha: int) -> str:
    """`#rrggbb` renginden yarı saydam `rgba(...)` metni üretir.

    Qt QSS `rgba(r, g, b, a)` biçimini anlar. Belirteç olarak saklanan renkler
    düz `#rrggbb` biçiminde tutulur; yalnızca dolgu üretirken şeffaflık eklenir.
    """
    r, g, b = _hex_to_rgb(hex_color)
    clamped = max(0, min(255, int(alpha)))
    return f"rgba({r}, {g}, {b}, {clamped})"


# ---------------------------------------------------------------------------
# Palet erişimi
# ---------------------------------------------------------------------------
def get_theme(theme_key: Optional[str] = None) -> Dict[str, str]:
    """Verilen temanın (varsayılan: etkin tema) palet belirteçlerini döndürür."""
    key = (theme_key or _ACTIVE_THEME or DEFAULT_THEME).lower()
    palette = THEME_PALETTES.get(key)
    if palette is None:
        return dict(THEME_PALETTES[DEFAULT_THEME])
    return dict(palette)


def current_palette() -> Dict[str, str]:
    """Şu anda etkin olan temanın palet kopyasını döndürür."""
    return get_theme(_ACTIVE_THEME)


def set_active_theme(theme_key: str) -> str:
    """Etkin temayı günceller, dinleyicileri bilgilendirir ve anahtarı döndürür.

    Bilinmeyen bir anahtar verildiğinde varsayılan temaya düşer.
    """
    global _ACTIVE_THEME
    key = (theme_key or "").lower()
    if key not in THEME_PALETTES:
        key = DEFAULT_THEME
    _ACTIVE_THEME = key
    _notify_theme_listeners()
    return key


def resolve_token(token: str, theme_key: Optional[str] = None, fallback: str = "#888888") -> str:
    """Paletten tek bir belirteç okur; yoksa güvenli bir yedege düşer."""
    return get_theme(theme_key).get(token, fallback)


def get_available_themes() -> Dict[str, str]:
    """Kullanılabilir tema anahtarlarını ve görünen adlarını döndürür."""
    return {key: pal["name"] for key, pal in THEME_PALETTES.items()}


def is_dark_theme(theme_key: Optional[str] = None) -> bool:
    """Verilen temanın koyu olup olmadığını belirler.

    Özel çizim yapan bileşenler (halka, gölge) yönü bu bilgiye göre ayarlar.
    """
    return relative_luminance(resolve_token("bg_main", theme_key)) < 0.5


# ---------------------------------------------------------------------------
# QSS üretimi
# ---------------------------------------------------------------------------
def get_theme_stylesheet(theme_key: Optional[str] = None) -> str:
    """Seçilen tema için eksiksiz PyQt6 QSS stil sayfasını üretir.

    Tüm renkler paletten gelir; stil sayfasında hiçbir renk sabit kodlanmaz.
    """
    pal = get_theme(theme_key)
    key = (theme_key or _ACTIVE_THEME).lower()
    if key not in THEME_PALETTES:
        key = DEFAULT_THEME

    return f"""
    /* ===================================================================
       AnonVoid Ortak Stil Sayfası — tema: {pal["name"]}
       Renklerin tamamı gui.themes paletinden gelir.
       =================================================================== */

    QMainWindow, QDialog, QWidget#rootPane {{
        background-color: {pal["bg_main"]};
        color: {pal["text_primary"]};
        font-family: {UI_FONT_STACK};
        font-size: 13px;
    }}

    QWidget {{
        color: {pal["text_primary"]};
    }}

    QWidget:disabled {{
        color: {pal["text_muted"]};
    }}

    /* --- Üst Uygulama Çubuğu ------------------------------------------- */
    #appBar {{
        background-color: {pal["bg_sidebar"]};
        border-bottom: 1px solid {pal["border"]};
    }}

    #appBarTitle {{
        font-size: 15px;
        font-weight: 600;
        color: {pal["text_primary"]};
        background: transparent;
    }}

    #appBarSubtitle {{
        font-size: 11px;
        color: {pal["text_muted"]};
        background: transparent;
    }}

    #brandMark {{
        font-size: 16px;
        font-weight: 700;
        color: {pal["accent"]};
        background: transparent;
    }}

    /* --- Sol Kenar Çubuğu ---------------------------------------------- */
    #sidebarFrame {{
        background-color: {pal["bg_sidebar"]};
        border-right: 1px solid {pal["border"]};
    }}

    #sidebarTitle {{
        font-size: 14px;
        font-weight: 700;
        color: {pal["text_primary"]};
        background: transparent;
    }}

    #sidebarSubtitle {{
        font-size: 10px;
        color: {pal["text_muted"]};
        background: transparent;
    }}

    #sidebarSection {{
        font-size: 10px;
        font-weight: 700;
        color: {pal["text_muted"]};
        background: transparent;
        padding: 0px;
    }}

    #sidebarVersion {{
        font-size: 9px;
        font-weight: 700;
        color: {pal["text_muted"]};
        background-color: {pal["bg_surface"]};
        border: 1px solid {pal["border"]};
        border-radius: 6px;
        padding: 3px 8px;
    }}

    /* Gösterge paneli kaydırma alanı: çerçevesiz ve saydam. */
    QScrollArea#dashboardScroll {{
        background: transparent;
        border: none;
    }}
    QScrollArea#dashboardScroll > QWidget > QWidget {{
        background: transparent;
    }}
    #dashboardPage {{
        background: transparent;
    }}

    /* Kenar çubuğu gezinme düğmeleri.
       Etkin öğe, yumuşak vurgulu bir "hap" görünümü alır; sol kenarlık
       kullanılmaz, böylece metin yatay olarak kaymaz (yerleşim titremesi olmaz). */
    QPushButton.navButton {{
        background-color: transparent;
        color: {pal["text_secondary"]};
        border: none;
        border-radius: 8px;
        text-align: left;
        padding: 9px 12px;
        margin: 2px 12px;
        font-size: 13px;
        font-weight: 500;
    }}
    QPushButton.navButton:hover {{
        background-color: {pal["bg_hover"]};
        color: {pal["text_primary"]};
    }}
    QPushButton.navButton[active="true"] {{
        background-color: {rgba(pal["accent"], 26)};
        color: {pal["accent"]};
        font-weight: 600;
    }}

    /* --- Kartlar -------------------------------------------------------- */
    .cardFrame {{
        background-color: {pal["bg_surface"]};
        border: 1px solid {pal["border"]};
        border-radius: 12px;
    }}
    .cardFrame[interactive="true"]:hover {{
        border: 1px solid {pal["border_strong"]};
        background-color: {pal["bg_surface_alt"]};
    }}

    .panelFrame {{
        background-color: {pal["bg_surface"]};
        border: 1px solid {pal["border"]};
        border-radius: 12px;
    }}

    .insetFrame {{
        background-color: {pal["bg_surface_alt"]};
        border: 1px solid {pal["border"]};
        border-radius: 10px;
    }}

    /* --- Tipografi ------------------------------------------------------ */
    #pageTitle {{
        font-size: 20px;
        font-weight: 700;
        color: {pal["text_primary"]};
        background: transparent;
    }}

    #pageSubtitle {{
        font-size: 12px;
        color: {pal["text_secondary"]};
        background: transparent;
    }}

    #sectionTitle {{
        font-size: 11px;
        font-weight: 700;
        color: {pal["text_muted"]};
        background: transparent;
    }}

    #cardTitle {{
        font-size: 13px;
        font-weight: 600;
        color: {pal["text_primary"]};
        background: transparent;
    }}

    #cardCaption {{
        font-size: 11px;
        color: {pal["text_muted"]};
        background: transparent;
    }}

    #metricValue {{
        font-family: {MONO_FONT_STACK};
        font-size: 19px;
        font-weight: 700;
        color: {pal["text_primary"]};
        background: transparent;
    }}

    #metricLabel {{
        font-size: 10px;
        color: {pal["text_muted"]};
        background: transparent;
    }}

    /* --- Düğmeler ------------------------------------------------------- */
    QPushButton {{
        background-color: {pal["bg_surface_alt"]};
        color: {pal["text_primary"]};
        border: 1px solid {pal["border"]};
        border-radius: 8px;
        padding: 8px 14px;
        font-size: 12px;
        font-weight: 600;
    }}
    QPushButton:hover {{
        background-color: {pal["bg_hover"]};
        border: 1px solid {pal["border_strong"]};
    }}
    QPushButton:pressed {{
        background-color: {pal["bg_surface"]};
    }}
    QPushButton:focus {{
        border: 1px solid {pal["accent"]};
    }}
    QPushButton:disabled {{
        background-color: {pal["bg_main"]};
        color: {pal["text_muted"]};
        border: 1px solid {pal["border"]};
    }}

    QPushButton#primaryButton {{
        background-color: {pal["accent"]};
        color: {pal["on_accent"]};
        border: 1px solid {pal["accent"]};
        border-radius: 9px;
        font-weight: 700;
        padding: 11px 18px;
    }}
    QPushButton#primaryButton:hover {{
        background-color: {pal["accent_hover"]};
        border: 1px solid {pal["accent_hover"]};
    }}
    QPushButton#primaryButton:pressed {{
        background-color: {pal["accent"]};
    }}
    QPushButton#primaryButton:disabled {{
        background-color: {pal["bg_surface_alt"]};
        color: {pal["text_muted"]};
        border: 1px solid {pal["border"]};
    }}

    QPushButton#dangerButton {{
        background-color: {pal["danger"]};
        color: #ffffff;
        border: 1px solid {pal["danger"]};
        font-weight: 700;
    }}
    QPushButton#dangerButton:hover {{
        background-color: {pal["danger"]};
        border: 1px solid {pal["text_primary"]};
    }}
    QPushButton#dangerButton:disabled {{
        background-color: {pal["bg_surface_alt"]};
        color: {pal["text_muted"]};
        border: 1px solid {pal["border"]};
    }}

    QPushButton#ghostButton {{
        background-color: transparent;
        color: {pal["text_secondary"]};
        border: 1px solid {pal["border"]};
        font-weight: 500;
    }}
    QPushButton#ghostButton:hover {{
        background-color: {pal["bg_hover"]};
        color: {pal["text_primary"]};
    }}

    QPushButton#linkButton {{
        background-color: transparent;
        color: {pal["accent"]};
        border: none;
        padding: 4px 6px;
        font-weight: 500;
        text-align: left;
    }}
    QPushButton#linkButton:hover {{
        color: {pal["accent_hover"]};
    }}

    /* --- Panik düğmesi: kenar çubuğunun en altında, iki aşamalı onaylı --- */
    QPushButton#panicButton {{
        background-color: {rgba(pal["danger"], 28)};
        color: {pal["danger"]};
        border: 1px solid {rgba(pal["danger"], 110)};
        border-radius: 8px;
        padding: 10px 12px;
        font-size: 12px;
        font-weight: 700;
    }}
    QPushButton#panicButton:hover {{
        background-color: {rgba(pal["danger"], 52)};
        border: 1px solid {pal["danger"]};
        color: {pal["danger"]};
    }}
    QPushButton#panicButton:disabled {{
        background-color: {pal["bg_surface"]};
        color: {pal["text_muted"]};
        border: 1px solid {pal["border"]};
    }}

    /* --- Panik onay kutusu (ikinci aşama) ------------------------------- */
    #panicArmLabel {{
        font-size: 11px;
        font-weight: 600;
        color: {pal["danger"]};
        background: transparent;
    }}

    /* --- Uygulama geneli uyarı şeridi ------------------------------------ */
    #noticeBanner {{
        background-color: {pal["bg_surface"]};
        border: 1px solid {pal["border"]};
        border-left: 3px solid {pal["text_muted"]};
        border-radius: 8px;
    }}
    #noticeBanner[token="warning"] {{
        background-color: {rgba(pal["warning"], 26)};
        border: 1px solid {rgba(pal["warning"], 90)};
        border-left: 3px solid {pal["warning"]};
    }}
    #noticeBanner[token="danger"] {{
        background-color: {rgba(pal["danger"], 26)};
        border: 1px solid {rgba(pal["danger"], 90)};
        border-left: 3px solid {pal["danger"]};
    }}
    #noticeBanner[token="info"] {{
        background-color: {rgba(pal["info"], 26)};
        border: 1px solid {rgba(pal["info"], 90)};
        border-left: 3px solid {pal["info"]};
    }}
    #noticeText {{
        font-size: 12px;
        color: {pal["text_primary"]};
        background: transparent;
    }}

    /* --- Giriş denetimleri ---------------------------------------------- */
    QLineEdit, QSpinBox, QComboBox, QPlainTextEdit {{
        background-color: {pal["bg_surface_alt"]};
        color: {pal["text_primary"]};
        border: 1px solid {pal["border"]};
        border-radius: 6px;
        padding: 6px 9px;
        selection-background-color: {pal["accent"]};
        selection-color: {pal["on_accent"]};
    }}
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {{
        border: 1px solid {pal["accent"]};
    }}
    QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{
        color: {pal["text_muted"]};
        background-color: {pal["bg_main"]};
    }}

    QComboBox::drop-down {{
        border: none;
        width: 22px;
    }}
    QComboBox::down-arrow {{
        image: url({_asset_url("chevron-down.png")});
        width: 12px;
        height: 12px;
    }}
    QComboBox QAbstractItemView {{
        background-color: {pal["bg_surface"]};
        color: {pal["text_primary"]};
        border: 1px solid {pal["border_strong"]};
        border-radius: 6px;
        selection-background-color: {pal["accent"]};
        selection-color: {pal["on_accent"]};
        outline: none;
        padding: 4px;
    }}

    QSpinBox::up-button, QSpinBox::down-button {{
        width: 0px;
        border: none;
        background: transparent;
    }}

    /* --- Onay kutuları ve radyo düğmeleri -------------------------------- */
    QCheckBox, QRadioButton {{
        color: {pal["text_primary"]};
        spacing: 8px;
        font-size: 12px;
    }}
    QCheckBox::indicator, QRadioButton::indicator {{
        width: 16px;
        height: 16px;
        border: 1px solid {pal["border_strong"]};
        background-color: {pal["bg_surface_alt"]};
    }}
    QCheckBox::indicator {{
        border-radius: 4px;
    }}
    QRadioButton::indicator {{
        border-radius: 9px;
    }}
    QCheckBox::indicator:hover, QRadioButton::indicator:hover {{
        border: 1px solid {pal["accent"]};
    }}
    QCheckBox::indicator:checked {{
        background-color: {pal["accent"]};
        border: 1px solid {pal["accent"]};
        image: url({_asset_url("check.png")});
    }}
    QRadioButton::indicator:checked {{
        background-color: {pal["accent"]};
        border: 4px solid {pal["bg_surface"]};
        outline: 1px solid {pal["accent"]};
    }}
    QCheckBox:disabled, QRadioButton:disabled {{
        color: {pal["text_muted"]};
    }}

    /* --- Grup kutuları --------------------------------------------------- */
    QGroupBox {{
        background-color: {pal["bg_surface"]};
        border: 1px solid {pal["border"]};
        border-radius: 10px;
        margin-top: 14px;
        padding-top: 10px;
        font-size: 12px;
        font-weight: 700;
        color: {pal["text_secondary"]};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 12px;
        top: 2px;
        padding: 0px 6px;
        color: {pal["text_secondary"]};
        background: transparent;
    }}

    /* --- İlerleme çubuğu ------------------------------------------------- */
    QProgressBar {{
        background-color: {pal["bg_surface_alt"]};
        border: 1px solid {pal["border"]};
        border-radius: 5px;
        height: 6px;
        text-align: center;
        color: transparent;
    }}
    QProgressBar::chunk {{
        background-color: {pal["accent"]};
        border-radius: 4px;
    }}

    /* --- Konsol / günlük ------------------------------------------------ */
    QTextEdit#consoleLog {{
        background-color: {pal["bg_main"]};
        color: {pal["text_secondary"]};
        border: 1px solid {pal["border"]};
        border-radius: 8px;
        font-family: {MONO_FONT_STACK};
        font-size: 11px;
        padding: 8px;
        selection-background-color: {pal["accent"]};
        selection-color: {pal["on_accent"]};
    }}

    /* --- Tablolar -------------------------------------------------------- */
    QTableWidget, QTableView {{
        background-color: {pal["bg_surface"]};
        alternate-background-color: {pal["bg_surface_alt"]};
        border: 1px solid {pal["border"]};
        border-radius: 8px;
        gridline-color: {pal["border"]};
        font-size: 12px;
    }}
    QHeaderView::section {{
        background-color: {pal["bg_surface_alt"]};
        color: {pal["text_secondary"]};
        border: none;
        border-bottom: 1px solid {pal["border"]};
        padding: 7px 8px;
        font-size: 10px;
        font-weight: 700;
    }}

    /* --- Kaydırma çubukları ---------------------------------------------- */
    QScrollArea {{
        border: none;
        background: transparent;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 8px;
        margin: 2px;
    }}
    QScrollBar::handle:vertical {{
        background: {pal["border_strong"]};
        border-radius: 4px;
        min-height: 32px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {pal["text_muted"]};
    }}
    QScrollBar:horizontal {{
        background: transparent;
        height: 8px;
        margin: 2px;
    }}
    QScrollBar::handle:horizontal {{
        background: {pal["border_strong"]};
        border-radius: 4px;
        min-width: 32px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {pal["text_muted"]};
    }}
    QScrollBar::add-line, QScrollBar::sub-line {{
        width: 0px;
        height: 0px;
        border: none;
        background: transparent;
    }}
    QScrollBar::add-page, QScrollBar::sub-page {{
        background: transparent;
    }}

    /* --- Ayırıcı --------------------------------------------------------- */
    QSplitter::handle {{
        background-color: {pal["border"]};
    }}
    QSplitter::handle:horizontal {{
        width: 1px;
    }}

    /* --- İpuçları ve menüler --------------------------------------------- */
    QToolTip {{
        background-color: {pal["bg_surface_alt"]};
        color: {pal["text_primary"]};
        border: 1px solid {pal["border_strong"]};
        border-radius: 6px;
        padding: 5px 7px;
        font-size: 11px;
    }}

    QMenu {{
        background-color: {pal["bg_surface"]};
        border: 1px solid {pal["border_strong"]};
        border-radius: 8px;
        padding: 5px;
    }}
    QMenu::item {{
        padding: 7px 22px 7px 12px;
        border-radius: 5px;
        font-size: 12px;
    }}
    QMenu::item:selected {{
        background-color: {pal["bg_hover"]};
    }}
    QMenu::separator {{
        height: 1px;
        background: {pal["border"]};
        margin: 5px 8px;
    }}

    /* --- Durum çubuğu ---------------------------------------------------- */
    QStatusBar {{
        background-color: {pal["bg_sidebar"]};
        border-top: 1px solid {pal["border"]};
        color: {pal["text_muted"]};
        font-size: 11px;
    }}
    QStatusBar::item {{
        border: none;
    }}

    /* --- Bölücü ve seçim renkleri ----------------------------------------- */
    ::selection {{
        background-color: {rgba(pal["accent"], 110)};
    }}
    """


def apply_theme_to_app(app: Any, theme_key: Optional[str] = None) -> str:
    """Verilen temayı QApplication nesnesine uygular ve etkin anahtarı döndürür.

    Etkin tema burada güncellenir; böylece temadan okuyan özel çizimli
    bileşenler de anında yeni paleti kullanmaya başlar.
    """
    key = set_active_theme(theme_key or _ACTIVE_THEME)
    if hasattr(app, "setStyleSheet"):
        app.setStyleSheet(get_theme_stylesheet(key))
    return key


def palette_contrast_report(theme_key: Optional[str] = None) -> Dict[str, float]:
    """Bir temadaki ana metin çiftlerinin kontrast oranlarını döndürür.

    Tasarım regresyonlarını (örneğin koyu zeminde okunamayan metin) erken
    yakalamak ve testlerde doğrulama yapmak için kullanılır.
    """
    pal = get_theme(theme_key)
    return {
        "text_primary/bg_surface": contrast_ratio(pal["text_primary"], pal["bg_surface"]),
        "text_secondary/bg_surface": contrast_ratio(pal["text_secondary"], pal["bg_surface"]),
        "text_muted/bg_surface": contrast_ratio(pal["text_muted"], pal["bg_surface"]),
        "text_primary/bg_app": contrast_ratio(pal["text_primary"], pal["bg_main"]),
        "text_muted/bg_sidebar": contrast_ratio(pal["text_muted"], pal["bg_sidebar"]),
        "accent/bg_surface": contrast_ratio(pal["accent"], pal["bg_surface"]),
        "on_accent/accent": contrast_ratio(pal["on_accent"], pal["accent"]),
        "success/bg_surface": contrast_ratio(pal["success"], pal["bg_surface"]),
        "warning/bg_surface": contrast_ratio(pal["warning"], pal["bg_surface"]),
        "danger/bg_surface": contrast_ratio(pal["danger"], pal["bg_surface"]),
    }
