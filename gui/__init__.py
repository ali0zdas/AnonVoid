"""AnonVoid - Grafik Kullanıcı Arayüzü (GUI) Modülü.

PyQt6 tabanlı gösterge paneli (dashboard), adli temizlik matrisi,
canlı ağ grafiği, sızıntı test ekranı ve modern görsel temaları barındırır.
"""

import sys
import os

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
