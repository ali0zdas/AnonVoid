"""AnonVoid - Gömülü tipografi yükleyicisi.

Arayüzün her sistemde aynı görünmesi için Inter yazı tipi uygulamayla birlikte
gelir. Sistemde Inter kurulu olmasa bile tipografi bozulmaz; DejaVu Sans gibi
genel bir yedeğe düşmez.

Inter, SIL Open Font License 1.1 ile dağıtılır (bkz. assets/fonts/OFL.txt).
"""

from __future__ import annotations

import os
import sys
from typing import List

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

FONT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "fonts")

# Yalnızca arayüzde kullanılan ağırlıklar gömülür (dosya boyutunu düşük tutar).
_FONT_FILES: tuple[str, ...] = (
    "Inter-Regular.ttf",
    "Inter-Medium.ttf",
    "Inter-SemiBold.ttf",
    "Inter-Bold.ttf",
)

_loaded_family: str = ""
_load_attempted: bool = False


def load_bundled_fonts() -> str:
    """Gömülü yazı tiplerini Qt'ye kaydeder ve aile adını döndürür.

    QApplication oluşturulmadan çağrılırsa sessizce boş metin döner; bu durumda
    tema yığını sistemde bulunan ilk yazı tipine düşer.
    """
    global _loaded_family, _load_attempted
    if _load_attempted:
        return _loaded_family
    _load_attempted = True

    try:
        from PyQt6.QtWidgets import QApplication
    except Exception:
        return ""

    if QApplication.instance() is None:
        # Uygulama nesnesi yokken font kaydı yapılamaz; sonraki çağrıda tekrar dene.
        _load_attempted = False
        return ""

    try:
        from PyQt6.QtGui import QFontDatabase
    except Exception:
        return ""

    families: List[str] = []
    for name in _FONT_FILES:
        path = os.path.join(FONT_DIR, name)
        if not os.path.isfile(path):
            continue
        font_id = QFontDatabase.addApplicationFont(path)
        if font_id >= 0:
            families.extend(QFontDatabase.applicationFontFamilies(font_id))

    if "Inter" in families:
        _loaded_family = "Inter"
    elif families:
        _loaded_family = families[0]

    # Uygulama genel yazı tipini de Inter'e taşı; böylece QSS'te ailesi
    # belirtilmemiş düğme ve etiketler sistem varsayılanına düşmez.
    if _loaded_family:
        app = QApplication.instance()
        if app is not None:
            base_font = app.font()
            base_font.setFamilies([_loaded_family, "DejaVu Sans", "sans-serif"])
            app.setFont(base_font)
    return _loaded_family


def ui_font_family() -> str:
    """Arayüz için kullanılacak yazı tipi ailesini döndürür."""
    return _loaded_family or "Inter"
