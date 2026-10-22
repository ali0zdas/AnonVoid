import os
import sys

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QPixmap
from gui.main_window import MainWindow

# Polling'i etkisiz hale getir
MainWindow._poll_daemon_status = lambda self: None

app = QApplication.instance()
if app is None:
    app = QApplication(sys.argv)

win = MainWindow()
win.resize(1220, 750)
win.show()

# Canlı korumalı durumu uygula
win._daemon_online = True
win.status_ring.set_status("CONNECTED")
win.btn_connect.setText("BAĞLANTIYI KES")
win.btn_connect.setEnabled(True)
win.btn_new_circuit.setEnabled(True)
win.speed_bar.update_info("185.220.101.42 (Almanya · Tor Çıkış Düğümü)", True, "DNSCrypt 5353 Şifreli · Sızıntı Yok")
win.tile_tor.set_value("185.220.101.42", "success")
win.tile_dns.set_value("UDP: 5353 [ŞİFRELİ]", "success")
win.tile_renewal.set_value("14:28:10", "accent")
win.tile_uptime.set_value("4 sa 18 dk", "text_primary")
win.score_pill.set_state("%100 KORUMALI", "success")
win.daemon_pill.set_state("Daemon bağlı", "success")

# Servis kartları
win.card_tor.set_state("Aktif", "success")
win.card_tor.set_detail("TransPort: 9040 · SOCKS5: 9050")
win.card_dns.set_state("Aktif", "success")
win.card_dns.set_detail("DNSCrypt: 5353 · DoH Korumalı")
win.card_mac.set_state("Uygulandı", "success")
win.card_mac.set_detail("Ağ Arayüzü: Sahte OUI")
win.card_forensics.set_state("Çalıştırıldı", "success")
win.card_forensics.set_detail("RAM, Swap, Shell Hijyeni")

# Canlı throughput grafiğine korumalı veri gönder
win.traffic_chart.set_protected(True, "Tor TransPort (9040) + DNSCrypt (5353) [ŞİFRELİ]")
win.traffic_chart.push_data(245.8, 52.4)

app.processEvents()

pixmap = QPixmap(win.size())
win.render(pixmap)
output_path = r"G:\Linux FP Cleaner\gui_dashboard_pro.png"
pixmap.save(output_path, "PNG")
print("RENDER_SUCCESS:", output_path)
win.close()
