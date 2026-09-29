"""AnonVoid - Adli İz Temizleme (Forensics) Modülü.

Bu modül; shell geçmişi, sistem günlükleri, önbellekler, bellek/swap hijyeni,
SSD TRIM ve düşük seviyeli C bellek sıfırlama mekanizmalarını barındırır.
"""

import sys
import os

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
