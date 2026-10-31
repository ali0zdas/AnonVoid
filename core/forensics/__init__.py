"""AnonVoid - Adli İz Temizleme (Forensics) Modülü.

Bu modül; shell geçmişi, sistem günlükleri, önbellekler, bellek/swap hijyeni,
SSD TRIM, meta veri imha (Exif/MAT2) ve düşük seviyeli C bellek sıfırlama mekanizmalarını barındırır.
"""

from __future__ import annotations

import os
import sys

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from core.forensics.manager import ForensicsManager

__all__ = ["ForensicsManager"]
