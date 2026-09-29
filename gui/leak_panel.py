"""AnonVoid - Canlı Adli Ağ Sızıntı Test Paneli (Leak Test Dashboard).

Bu modül; kullanıcının tek bir tıklamayla Tor Exit IP'sini, DNS sızıntılarını,
IPv6 drop durumunu ve WebRTC STUN UDP kaçaklarını denetleyebileceği görsel test ekranıdır.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.daemon_client import AsyncDaemonWorker, DaemonClient


class LeakPanel(QWidget):
    """Canlı adli ağ sızıntı test ekranı."""

    def __init__(self, client: DaemonClient, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.client = client
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)

        # Başlık ve Açıklama
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        title = QLabel("Canlı Adli Ağ Sızıntı Test Paketi (Leak Test Suite)", self)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        header_layout.addWidget(title)

        desc = QLabel(
            "Ağ trafiğinizin Tor, DNSCrypt ve IPv6 filtrelerinden dışarı sızıp sızmadığını gerçek zamanlı test edin.",
            self,
        )
        desc.setStyleSheet("font-size: 12px; color: #888888;")
        header_layout.addWidget(desc)
        main_layout.addLayout(header_layout)

        # Genel Durum Kartı
        self.summary_box = QFrame(self)
        self.summary_box.setProperty("class", "cardFrame")
        self.summary_box.setMinimumHeight(70)
        summary_layout = QHBoxLayout(self.summary_box)

        self.summary_label = QLabel("Test Bekleniyor: Sonuçları görmek için testi çalıştırın.", self)
        self.summary_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #888888;")
        summary_layout.addWidget(self.summary_label)

        summary_layout.addStretch()

        self.btn_run_test = QPushButton("🔍 SIZINTI TESTİNİ ÇALIŞTIR", self)
        self.btn_run_test.setObjectName("primaryButton")
        self.btn_run_test.setMinimumHeight(38)
        self.btn_run_test.clicked.connect(self.run_test)
        summary_layout.addWidget(self.btn_run_test)

        main_layout.addWidget(self.summary_box)

        # 4 Ana Test Kartı (Grid)
        grid_group = QGroupBox("Adli Güvenlik ve Sızıntı Göstergeleri", self)
        grid_group.setStyleSheet("font-weight: bold; font-size: 13px;")
        grid_layout = QGridLayout(grid_group)
        grid_layout.setContentsMargins(16, 16, 16, 16)
        grid_layout.setSpacing(14)

        # 1. Tor Exit IP Kartı
        self.card_tor = self._create_indicator_card("🧅 Tor Çıkış IP Doğrulaması", "IP: Henüz test edilmedi")
        grid_layout.addWidget(self.card_tor, 0, 0)

        # 2. DNS Sızıntı Kartı
        self.card_dns = self._create_indicator_card("🌐 DNS Sızıntı Koruması", "DNS: Henüz test edilmedi")
        grid_layout.addWidget(self.card_dns, 0, 1)

        # 3. IPv6 Kalkan Kartı
        self.card_ipv6 = self._create_indicator_card("🛡️ IPv6 Sızıntı Kalkanı (Drop)", "IPv6: Henüz test edilmedi")
        grid_layout.addWidget(self.card_ipv6, 1, 0)

        # 4. WebRTC STUN Kaçak Kartı
        self.card_webrtc = self._create_indicator_card("📡 WebRTC UDP STUN Sızıntısı", "WebRTC: Henüz test edilmedi")
        grid_layout.addWidget(self.card_webrtc, 1, 1)

        main_layout.addWidget(grid_group)

        # Sistem Kimliği ve Parmak İzi Kartı
        id_group = QGroupBox("Sistem Kimliği ve Saat Dilimi (Timezone) İfşası", self)
        id_group.setStyleSheet("font-weight: bold; font-size: 13px;")
        id_layout = QVBoxLayout(id_group)
        id_layout.setContentsMargins(16, 16, 16, 16)

        self.label_identity = QLabel("Makine Adı (Hostname) ve Yerel Saat Dilimi bilgisi test edilmedi.", self)
        self.label_identity.setStyleSheet("font-size: 12px; color: #888888;")
        self.label_identity.setWordWrap(True)
        id_layout.addWidget(self.label_identity)

        main_layout.addWidget(id_group)
        main_layout.addStretch()

    def _create_indicator_card(self, title: str, initial_val: str) -> QFrame:
        """Sızıntı gösterge kartı oluşturur."""
        frame = QFrame(self)
        frame.setProperty("class", "cardFrame")
        layout = QVBoxLayout(frame)
        layout.setSpacing(6)

        title_lbl = QLabel(title, frame)
        title_lbl.setStyleSheet("font-size: 13px; font-weight: bold; color: #ffffff;")
        layout.addWidget(title_lbl)

        val_lbl = QLabel(initial_val, frame)
        val_lbl.setObjectName("val_label")
        val_lbl.setStyleSheet("font-size: 12px; color: #888888;")
        layout.addWidget(val_lbl)

        return frame

    def run_test(self) -> None:
        """Sızıntı testini asenkron olarak yürütür."""
        self.btn_run_test.setEnabled(False)
        self.summary_label.setText("Sızıntı testleri yürütülüyor, lütfen bekleyin...")
        self.summary_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #00d4ff;")

        def _on_success(data: Dict[str, Any]) -> None:
            self.btn_run_test.setEnabled(True)
            self._update_results(data)

        def _on_error(err_msg: str) -> None:
            self.btn_run_test.setEnabled(True)
            self.summary_label.setText(f"Test Başarısız: {err_msg}")
            self.summary_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #ff3366;")

        worker = AsyncDaemonWorker(
            client=self.client,
            action="leak_test",
            timeout=30.0,
            on_success=_on_success,
            on_error=_on_error,
        )
        worker.start()

    def _update_results(self, data: Dict[str, Any]) -> None:
        """Dönen test raporunu arayüz kartlarına işler."""
        is_anon = data.get("is_fully_anonymous", False)

        # Genel Özet
        if is_anon:
            self.summary_label.setText("🛡️ %100 ANONİM VE GÜVENLİ: Hiçbir sızıntı tespit edilmedi.")
            self.summary_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #00ff88;")
        else:
            self.summary_label.setText("⚠️ DİKKAT: Bazı testler koruma altında olmadığınızı gösteriyor!")
            self.summary_label.setStyleSheet("font-size: 14px; font-weight: bold; color: #ffaa00;")

        # Tor Kartı
        tor = data.get("tor", {})
        tor_lbl = self.card_tor.findChild(QLabel, "val_label")
        if tor_lbl:
            ip = tor.get("ip", "Bilinmiyor")
            is_tor = tor.get("is_tor", False)
            color = "#00ff88" if is_tor else "#ffaa00"
            status_txt = "Tor Exit Node (Güvenli)" if is_tor else "Tor Dışı IP (Açık)"
            tor_lbl.setText(f"IP: {ip} ({status_txt})")
            tor_lbl.setStyleSheet(f"font-size: 12px; color: {color}; font-weight: bold;")

        # DNS Kartı
        dns = data.get("dns", {})
        dns_lbl = self.card_dns.findChild(QLabel, "val_label")
        if dns_lbl:
            dns_ok = dns.get("tor_dns_responsive", False)
            color = "#00ff88" if dns_ok else "#ff3366"
            dns_lbl.setText(f"DNS Yanıtı: {dns.get('resolved_ip', 'Bilinmiyor')} (Tor DNSPort Aktif)")
            dns_lbl.setStyleSheet(f"font-size: 12px; color: {color}; font-weight: bold;")

        # IPv6 Kartı
        ipv6 = data.get("ipv6", {})
        ipv6_lbl = self.card_ipv6.findChild(QLabel, "val_label")
        if ipv6_lbl:
            leak = ipv6.get("leak_detected", False)
            color = "#ff3366" if leak else "#00ff88"
            ipv6_lbl.setText(ipv6.get("message", "Test Edildi"))
            ipv6_lbl.setStyleSheet(f"font-size: 12px; color: {color}; font-weight: bold;")

        # WebRTC Kartı
        webrtc = data.get("webrtc", {})
        webrtc_lbl = self.card_webrtc.findChild(QLabel, "val_label")
        if webrtc_lbl:
            leak = webrtc.get("leak_detected", False)
            color = "#ff3366" if leak else "#00ff88"
            webrtc_lbl.setText(webrtc.get("message", "Test Edildi"))
            webrtc_lbl.setStyleSheet(f"font-size: 12px; color: {color}; font-weight: bold;")

        # Sistem Kimliği
        ident = data.get("system_identity", {})
        h_name = ident.get("hostname", "Bilinmiyor")
        tz = ident.get("timezone", "Bilinmiyor")
        warn = ident.get("warning", "")
        self.label_identity.setText(f"Makine Adı (Hostname): {h_name} | Saat Dilimi: {tz}\n{warn}")
