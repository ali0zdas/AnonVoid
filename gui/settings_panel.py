"""AnonVoid - Ayarlar Paneli (Settings Dashboard).

Bu modül; genel ağ portları, DoH bloklama, IPv6 koruması, MAC sahteleme
ve görsel tema tercihlerinin yapılandırıldığı kontrol sekmesini içerir.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Callable, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

try:
    from PyQt6.QtCore import Qt, pyqtSignal
    from PyQt6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QFormLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMessageBox,
        QPushButton,
        QScrollArea,
        QSpinBox,
        QVBoxLayout,
        QWidget,
    )
except ImportError:
    pass

from core.config import DEFAULT_CONFIG, safe_load_config, safe_save_config
from gui.themes import current_palette, get_available_themes
from gui.widgets import guarded_style_sheet

logger = logging.getLogger("AnonVoidSettings")


class SettingsPanel(QWidget):
    """AnonVoid Yapılandırma ve Ağ Ayarları Paneli."""

    theme_changed = pyqtSignal(str)
    config_saved = pyqtSignal(dict)

    def __init__(self, config_path: Optional[str] = None, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.config_path = config_path or os.path.expanduser("~/.config/anonvoid/config.json")
        self.config_data = safe_load_config(self.config_path, fallback_to_default=True)
        self._init_ui()
        self.load_settings_to_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 22)
        main_layout.setSpacing(16)

        section = QLabel("YAPILANDIRMA", self)
        section.setObjectName("sectionTitle")
        main_layout.addWidget(section)

        # Kaydırılabilir Alan
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)

        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(16)

        # 1. Ağ Omurgası Ayarları
        net_group = QGroupBox("Ağ Omurgası ve Güvenlik Duvarı Ayarları", container)
        net_form = QFormLayout(net_group)
        net_form.setContentsMargins(16, 16, 16, 16)
        net_form.setSpacing(10)

        self.spin_trans_port = QSpinBox(net_group)
        self.spin_trans_port.setRange(1024, 65535)
        net_form.addRow("Tor TransPort (TCP Yönlendirme):", self.spin_trans_port)

        self.spin_dns_port = QSpinBox(net_group)
        self.spin_dns_port.setRange(1024, 65535)
        net_form.addRow("Tor DNSPort (DNS Yönlendirme):", self.spin_dns_port)

        self.spin_socks_port = QSpinBox(net_group)
        self.spin_socks_port.setRange(1024, 65535)
        net_form.addRow("Tor SOCKS5 Port:", self.spin_socks_port)

        self.spin_control_port = QSpinBox(net_group)
        self.spin_control_port.setRange(1024, 65535)
        net_form.addRow("Tor ControlPort (Devre Yenileme):", self.spin_control_port)

        self.spin_dnscrypt_port = QSpinBox(net_group)
        self.spin_dnscrypt_port.setRange(1024, 65535)
        net_form.addRow("DNSCrypt-Proxy Port:", self.spin_dnscrypt_port)

        self.spin_circuit_interval = QSpinBox(net_group)
        self.spin_circuit_interval.setRange(30, 86400)
        self.spin_circuit_interval.setSuffix(" saniye")
        net_form.addRow("Otomatik Kimlik (Devre) Yenileme Periyodu:", self.spin_circuit_interval)

        self.chk_block_doh = QCheckBox("DoH (DNS-over-HTTPS) Sunucularını Engelle (Port 443 Drop)", net_group)
        net_form.addRow("", self.chk_block_doh)

        self.chk_drop_ipv6 = QCheckBox("Tüm Giden IPv6 Trafiğini Kapat (IPv6 Sızıntı Koruması)", net_group)
        net_form.addRow("", self.chk_drop_ipv6)

        self.chk_mac_randomize = QCheckBox("Ağ Arayüzü MAC Adresini Rastgele Değiştir", net_group)
        net_form.addRow("", self.chk_mac_randomize)

        self.chk_mac_in_place = QCheckBox("MAC Değişimini Yerinde Yap (In-Place / NetworkManager Koruması)", net_group)
        net_form.addRow("", self.chk_mac_in_place)

        container_layout.addWidget(net_group)

        # 2. Görünüm ve Uygulama Tercihleri
        app_group = QGroupBox("Uygulama Tercihleri ve Görünüm", container)
        app_form = QFormLayout(app_group)
        app_form.setContentsMargins(16, 16, 16, 16)
        app_form.setSpacing(10)

        theme_badge = QLabel("Dark (Koyu Profesyonel — Standart Sabit Tema)", app_group)
        theme_badge.setObjectName("cardCaption")
        app_form.addRow("Görsel Tema:", theme_badge)

        self.combo_theme = QComboBox(app_group)
        self.combo_theme.addItem("Dark (Koyu Profesyonel)", "oled")
        self.combo_theme.setVisible(False)

        self.chk_close_to_tray = QCheckBox("Pencere Kapatıldığında Sistem Tepsisine Küçül", app_group)
        app_form.addRow("", self.chk_close_to_tray)

        self.chk_auto_leak_test = QCheckBox("Bağlantı Kurulduğunda Otomatik Sızıntı Testi Çalıştır", app_group)
        app_form.addRow("", self.chk_auto_leak_test)

        container_layout.addWidget(app_group)
        container_layout.addStretch()

        scroll.setWidget(container)
        main_layout.addWidget(scroll)

        # Kaydet Butonları
        btn_bar = QHBoxLayout()
        btn_bar.addStretch()

        self.status_save_label = QLabel("", self)
        btn_bar.addWidget(self.status_save_label)

        self.btn_save = QPushButton("AYARLARI KAYDET", self)
        self.btn_save.setObjectName("primaryButton")
        self.btn_save.setMinimumHeight(40)
        self.btn_save.setMinimumWidth(170)
        self.btn_save.clicked.connect(self.save_settings)
        btn_bar.addWidget(self.btn_save)

        main_layout.addLayout(btn_bar)

    def load_settings_to_ui(self) -> None:
        """Yapılandırma dosyasındaki verileri arayüze yükler."""
        net = self.config_data.get("network", DEFAULT_CONFIG["network"])
        self.spin_trans_port.setValue(net.get("tor_trans_port", 9040))
        self.spin_dns_port.setValue(net.get("tor_dns_port", 5300))
        self.spin_socks_port.setValue(net.get("tor_socks_port", 9050))
        self.spin_control_port.setValue(net.get("tor_control_port", 9051))
        self.spin_dnscrypt_port.setValue(net.get("dnscrypt_port", 5380))
        self.spin_circuit_interval.setValue(net.get("circuit_interval_sec", 600))
        self.chk_block_doh.setChecked(net.get("block_doh", True))
        self.chk_drop_ipv6.setChecked(net.get("drop_ipv6", True))
        self.chk_mac_randomize.setChecked(net.get("mac_randomize", True))
        self.chk_mac_in_place.setChecked(net.get("mac_in_place", True))

        gui = self.config_data.get("gui", DEFAULT_CONFIG["gui"])
        current_theme = gui.get("theme", "oled")
        idx = self.combo_theme.findData(current_theme)
        if idx >= 0:
            self.combo_theme.setCurrentIndex(idx)

        self.chk_close_to_tray.setChecked(gui.get("close_to_tray", True))
        self.chk_auto_leak_test.setChecked(gui.get("auto_leak_test_on_connect", True))

    def _on_theme_selected(self) -> None:
        """Tema kutusundan yeni bir tema seçildiğinde sinyal üretir."""
        theme_key = self.combo_theme.currentData()
        self.theme_changed.emit(theme_key)

    def save_settings(self) -> None:
        """Arayüzdeki güncel ayarları doğrular ve güvenle diske kaydeder."""
        theme_key = "oled"

        updated_config = {
            "network": {
                "tor_trans_port": self.spin_trans_port.value(),
                "tor_dns_port": self.spin_dns_port.value(),
                "tor_socks_port": self.spin_socks_port.value(),
                "tor_control_port": self.spin_control_port.value(),
                "dnscrypt_port": self.spin_dnscrypt_port.value(),
                "circuit_interval_sec": self.spin_circuit_interval.value(),
                "block_doh": self.chk_block_doh.isChecked(),
                "drop_ipv6": self.chk_drop_ipv6.isChecked(),
                "mac_randomize": self.chk_mac_randomize.isChecked(),
                "mac_in_place": self.chk_mac_in_place.isChecked(),
            },
            "gui": {
                "theme": theme_key,
                "close_to_tray": self.chk_close_to_tray.isChecked(),
                "auto_leak_test_on_connect": self.chk_auto_leak_test.isChecked(),
            },
        }

        try:
            safe_save_config(self.config_path, updated_config)
            self.config_data = safe_load_config(self.config_path)
            self._set_save_status("Ayarlar başarıyla kaydedildi!", "success")
            self.config_saved.emit(self.config_data)
        except Exception as err:
            self._set_save_status(f"Kayıt hatası: {err}", "danger")

    def _set_save_status(self, text: str, token: str) -> None:
        """Kaydetme durumunu temadan alınan renkle gösterir."""
        pal = current_palette()
        self.status_save_label.setText(text)
        guarded_style_sheet(
            self.status_save_label,
            f"color: {pal.get(token, pal['text_secondary'])}; font-weight: 600; background: transparent;",
        )
