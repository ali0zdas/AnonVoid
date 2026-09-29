"""AnonVoid - Ağ ve Gizlilik (Network Stack) Modülü.

Bu modül; Tor şeffaf proxy, nftables güvenlik duvarı, DNSCrypt,
MAC sahteleme, sızıntı test ve acil panik modüllerini içerir.
"""

import sys
import os

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
