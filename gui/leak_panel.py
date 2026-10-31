"""AnonVoid - Canlı Adli Ağ Sızıntı Test Paneli (Leak Test).

Bu modül; kullanıcının tek tıklamayla Tor çıkış IP'sini, DNS sızıntılarını,
IPv6 kaçağını ve WebRTC STUN açıklarını denetleyebileceği görsel test ekranıdır.

Tüm renkler `gui.themes` paletinden gelir; panel hiçbir rengi satır içi
sabit kodlamaz.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.daemon_client import AsyncDaemonWorker, DaemonClient
from gui.themes import current_palette, register_theme_listener
from gui.widgets import (
    GLYPH_DNS,
    GLYPH_LEAK,
    GLYPH_MAC,
    GLYPH_TOR,
    GlyphChip,
    guarded_style_sheet,
)


class _StatusText(QLabel):
    """Temadan renk alan, kendini yeniden boyayan durum metni."""

    def __init__(self, initial: str, token: str = "text_muted", parent: Optional[QWidget] = None) -> None:
        super().__init__(initial, parent)
        self.setObjectName("cardCaption")
        self.setWordWrap(True)
        self._token = token
        register_theme_listener(self._on_theme_changed)
        self._apply()

    def _on_theme_changed(self) -> None:
        self._apply()

    def set_status(self, text: str, token: str) -> None:
        """Metni ve anlam rengini günceller."""
        self.setText(text)
        self._token = token
        self._apply()

    def _apply(self) -> None:
        pal = current_palette()
        guarded_style_sheet(
            self,
            f"color: {pal.get(self._token, pal['text_muted'])};"
            " font-size: 12px; font-weight: 600; background: transparent;",
        )

    def changeEvent(self, event) -> None:  # noqa: N802
        self._apply()
        super().changeEvent(event)


class LeakPanel(QWidget):
    """Canlı adli ağ sızıntı test ekranı."""

    def __init__(self, client: DaemonClient, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.client = client
        self._init_ui()

    # ------------------------------------------------------------------
    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 22)
        main_layout.setSpacing(16)

        # Genel durum kartı
        summary = QFrame(self)
        summary.setProperty("class", "cardFrame")
        summary_layout = QHBoxLayout(summary)
        summary_layout.setContentsMargins(16, 14, 14, 14)
        summary_layout.setSpacing(12)

        self.summary_label = _StatusText("Test henüz çalıştırılmadı.", "text_muted")
        summary_layout.addWidget(self.summary_label, stretch=1)

        self.btn_run_test = QPushButton("TESTİ ÇALIŞTIR", summary)
        self.btn_run_test.setObjectName("primaryButton")
        self.btn_run_test.setMinimumHeight(38)
        self.btn_run_test.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_run_test.clicked.connect(self.run_test)
        summary_layout.addWidget(self.btn_run_test)
        main_layout.addWidget(summary)

        section = QLabel("GÜVENLİK GÖSTERGELERİ", self)
        section.setObjectName("sectionTitle")
        main_layout.addWidget(section)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.lbl_tor = self._create_indicator(
            "Tor Çıkış IP Doğrulaması", GLYPH_TOR, "Henüz test edilmedi", icon="network"
        )
        self.lbl_dns = self._create_indicator(
            "DNS Sızıntı Koruması", GLYPH_DNS, "Henüz test edilmedi", icon="dns"
        )
        self.lbl_ipv6 = self._create_indicator(
            "IPv6 Sızıntı Kalkanı", GLYPH_MAC, "Henüz test edilmedi", icon="globe"
        )
        self.lbl_webrtc = self._create_indicator(
            "WebRTC STUN Kaçağı", GLYPH_LEAK, "Henüz test edilmedi", icon="leak"
        )
        grid.addWidget(self.lbl_tor, 0, 0)
        grid.addWidget(self.lbl_dns, 0, 1)
        grid.addWidget(self.lbl_ipv6, 1, 0)
        grid.addWidget(self.lbl_webrtc, 1, 1)
        main_layout.addLayout(grid)

        section2 = QLabel("SİSTEM KİMLİĞİ", self)
        section2.setObjectName("sectionTitle")
        main_layout.addWidget(section2)

        identity = QFrame(self)
        identity.setProperty("class", "insetFrame")
        identity_layout = QVBoxLayout(identity)
        identity_layout.setContentsMargins(14, 12, 14, 12)
        self.label_identity = QLabel(
            "Makine adı ve yerel saat dilimi bilgisi henüz test edilmedi.", identity
        )
        self.label_identity.setObjectName("cardCaption")
        self.label_identity.setWordWrap(True)
        identity_layout.addWidget(self.label_identity)
        main_layout.addWidget(identity)

        main_layout.addStretch(1)

    def _create_indicator(self, title: str, glyph: str, initial: str, icon: str = "") -> QFrame:
        """Başlık + glif + durum metninden oluşan gösterge kartı üretir."""
        frame = QFrame(self)
        frame.setProperty("class", "cardFrame")
        frame.setMinimumHeight(104)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(9)
        chip = GlyphChip(glyph, "text_muted", 30, frame, icon=icon)
        head.addWidget(chip)
        title_lbl = QLabel(title, frame)
        title_lbl.setObjectName("cardTitle")
        title_lbl.setWordWrap(True)
        head.addWidget(title_lbl, stretch=1)
        layout.addLayout(head)

        status = _StatusText(initial, frame)
        status.setObjectName("val_label")
        layout.addWidget(status)
        frame.status_label = status
        return frame

    # ------------------------------------------------------------------
    def run_leak_test(self) -> None:
        """Sızıntı testini başlatır (`run_test` takma adı)."""
        self.run_test()

    def run_test(self) -> None:
        """Sızıntı testini arayüzü kilitlemeden yürütür."""
        self.btn_run_test.setEnabled(False)
        self.summary_label.set_status("Sızıntı testleri yürütülüyor, lütfen bekleyin…", "info")

        def _on_success(data: Dict[str, Any]) -> None:
            self.btn_run_test.setEnabled(True)
            self._update_results(data)

        def _on_error(err_msg: str) -> None:
            self.btn_run_test.setEnabled(True)
            self.summary_label.set_status(f"Test başarısız: {err_msg}", "danger")

        AsyncDaemonWorker(
            client=self.client,
            action="leak_test",
            # Test paketi dört ayrı ağ probu yapar (Tor çıkış IP, IPv6, DNS, STUN).
            # En kötü durumda her biri kendi zaman aşımını sürebildiği için 30s
            # yetersiz kalıyor ve istemci daemon'dan önce vazgeçiyordu.
            timeout=90.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()

    def _update_results(self, data: Dict[str, Any]) -> None:
        """Dönen test raporunu gösterge kartlarına işler."""
        is_anon = bool(data.get("is_fully_anonymous", False))
        if is_anon:
            self.summary_label.set_status("Tam anonimlik sağlandı: hiçbir sızıntı tespit edilmedi.", "success")
        else:
            self.summary_label.set_status(
                "Dikkat: bazı göstergeler koruma altında olmadığınızı gösteriyor.", "warning"
            )

        tor = data.get("tor", {})
        is_tor = bool(tor.get("is_tor", False))
        self.lbl_tor.status_label.set_status(
            f"{tor.get('ip', 'Bilinmiyor')} — {'Tor çıkış düğümü' if is_tor else 'Tor dışı, gerçek IP açıkta'}",
            "success" if is_tor else "danger",
        )

        dns = data.get("dns", {})
        dns_ok = bool(dns.get("tor_dns_responsive", False))
        self.lbl_dns.status_label.set_status(
            f"{dns.get('resolved_ip', 'Bilinmiyor')} — Tor DNSPort yanıt veriyor"
            if dns_ok
            else "Tor DNSPort yanıt vermiyor",
            "success" if dns_ok else "danger",
        )

        ipv6 = data.get("ipv6", {})
        ipv6_leak = bool(ipv6.get("leak_detected", False))
        self.lbl_ipv6.status_label.set_status(
            ipv6.get("message", "Test edildi"), "danger" if ipv6_leak else "success"
        )

        webrtc = data.get("webrtc", {})
        webrtc_leak = bool(webrtc.get("leak_detected", False))
        self.lbl_webrtc.status_label.set_status(
            webrtc.get("message", "Test edildi"), "danger" if webrtc_leak else "success"
        )

        ident = data.get("system_identity", {})
        warning = ident.get("warning", "")
        self.label_identity.setText(
            f"Makine adı: {ident.get('hostname', 'Bilinmiyor')}    ·    "
            f"Saat dilimi: {ident.get('timezone', 'Bilinmiyor')}"
            + (f"\n{warning}" if warning else "")
        )
