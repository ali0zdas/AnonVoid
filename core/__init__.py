"""AnonVoid - Çekirdek Modülü.

Bu modül, ayrıcalık ayrımı (privilege boundary), güvenli yapılandırma,
root IPC daemon'ı ve istemci iletişim altyapısını içerir.
"""

import sys
import os

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
