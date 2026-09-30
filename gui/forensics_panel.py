"""AnonVoid - Adli Temizlik Paneli (Forensics).

Bu modül; kullanıcının shell geçmişi, sistem günlükleri, önbellekler, bellek,
SSD TRIM ve boş alan sıfırlama modüllerini seçebileceği seçim matrisi, ilerleme
çubuğu ve canlı günlük konsolunu barındırır.

Tüm renkler `gui.themes` paletinden gelir.
"""

from __future__ import annotations

import os
import sys
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.daemon_client import AsyncDaemonWorker, DaemonClient
from gui.themes import current_palette
from gui.widgets import LogConsoleWidget, guarded_style_sheet


class ForensicsPanel(QWidget):
    """Adli iz temizleme seçim matrisi ve ilerleme paneli."""

    cleanup_started = pyqtSignal()
    cleanup_finished = pyqtSignal(dict)

    # (denetim, hedef anahtarı, etiket, açıklama)
    _MODULES = [
        ("chk_shell", "clean_shell_history", "Shell ve komut geçmişi", "bash, zsh, python, mysql izleri"),
        ("chk_journal", "clean_journal_logs", "Sistem günlükleri", "journald vakumu ve metin logları"),
        ("chk_cache", "clean_trash", "Önbellek ve MRU", "küçük resimler, recently-used, çöp kutusu"),
        ("chk_ram", "clean_memory_caches", "RAM ve takas alanı", "drop_caches, compact_memory, swapoff"),
        ("chk_trim", "ssd_trim", "Depolama ve SSD TRIM", "fstrim ile flash hücre sıfırlama"),
        ("chk_pkg", "clean_package_cache", "Paket önbelleği", "APT, Pacman, Flatpak, Snap önbellekleri"),
        ("chk_zero_space", "free_space_zeroing", "Boş alan sıfırlama", "Kullanılmayan alanın üzerine yazma (yavaş)"),
        ("chk_swap_zero", "clean_swap", "Takas alanını doldur", "Swap'i urandom ile yeniden yazma"),
    ]

    def __init__(self, client: DaemonClient, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.client = client
        for attr, _key, _label, _desc in self._MODULES:
            setattr(self, attr, None)
        self._init_ui()

    # ------------------------------------------------------------------
    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 22)
        main_layout.setSpacing(16)

        section = QLabel("TEMİZLİK MODÜLLERİ", self)
        section.setObjectName("sectionTitle")
        main_layout.addWidget(section)

        matrix = QFrame(self)
        matrix.setProperty("class", "cardFrame")
        matrix_layout = QGridLayout(matrix)
        matrix_layout.setContentsMargins(14, 14, 14, 14)
        matrix_layout.setSpacing(10)

        for index, (attr, _key, label, description) in enumerate(self._MODULES):
            checkbox = QCheckBox(f"{label} — {description}", matrix)
            checkbox.setChecked(index < 6)
            setattr(self, attr, checkbox)
            matrix_layout.addWidget(checkbox, index // 2, index % 2)
        main_layout.addWidget(matrix)

        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(8)

        self.btn_select_all = QPushButton("Tümünü Seç", self)
        self.btn_select_all.setObjectName("ghostButton")
        self.btn_select_all.clicked.connect(self._select_all)
        btn_layout.addWidget(self.btn_select_all)

        self.btn_clear_selection = QPushButton("Seçimi Temizle", self)
        self.btn_clear_selection.setObjectName("ghostButton")
        self.btn_clear_selection.clicked.connect(self._clear_selection)
        btn_layout.addWidget(self.btn_clear_selection)

        btn_layout.addStretch(1)

        self.status_label = QLabel("Hazır: temizlik modüllerini seçip başlatın.", self)
        self.status_label.setObjectName("cardCaption")
        btn_layout.addWidget(self.status_label)

        self.btn_start = QPushButton("ADLİ TEMİZLİĞİ BAŞLAT", self)
        self.btn_start.setObjectName("primaryButton")
        self.btn_start.setMinimumHeight(40)
        self.btn_start.setMinimumWidth(210)
        self.btn_start.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start.clicked.connect(self.start_cleanup)
        btn_layout.addWidget(self.btn_start)
        main_layout.addLayout(btn_layout)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        log_label = QLabel("İŞLEM GÜNLÜĞÜ", self)
        log_label.setObjectName("sectionTitle")
        main_layout.addWidget(log_label)

        self.console = LogConsoleWidget(self)
        self.console.setMinimumHeight(160)
        main_layout.addWidget(self.console, stretch=1)

    # ------------------------------------------------------------------
    def _all_checkboxes(self):
        return [getattr(self, attr) for attr, _k, _l, _d in self._MODULES]

    def _select_all(self) -> None:
        """Tüm modülleri seçer."""
        for checkbox in self._all_checkboxes():
            checkbox.setChecked(True)

    def _clear_selection(self) -> None:
        """Tüm seçimleri kaldırır."""
        for checkbox in self._all_checkboxes():
            checkbox.setChecked(False)

    def get_selected_targets(self) -> Dict[str, bool]:
        """Kullanıcının seçtiği modülleri hedef sözlüğü olarak döndürür."""
        selected = {
            key: getattr(self, attr).isChecked() for attr, key, _l, _d in self._MODULES
        }
        # Birbiriyle eşleşen alt hedefler, ana modülle aynı seçime bağlıdır.
        selected["clean_text_logs"] = selected["clean_journal_logs"]
        selected["clean_thumbnails"] = selected["clean_trash"]
        selected["clean_mru_cache"] = selected["clean_trash"]
        return selected

    def _set_status(self, text: str, token: str) -> None:
        pal = current_palette()
        self.status_label.setText(text)
        guarded_style_sheet(
            self.status_label,
            f"color: {pal.get(token, pal['text_secondary'])}; font-size: 12px; background: transparent;",
        )

    def start_cleanup(self) -> None:
        """Temizlik sürecini arayüzü kilitlemeden asenkron başlatır."""
        targets = self.get_selected_targets()
        if not any(targets.values()):
            self._set_status("En az bir modül seçmelisiniz.", "warning")
            return

        self.btn_start.setEnabled(False)
        self.progress_bar.setValue(10)
        self._set_status("Adli temizlik yürütülüyor…", "info")
        self.console.append_log("Temizlik talebi root daemon servisine iletildi.", "INFO")
        self.cleanup_started.emit()

        def _on_success(data: Dict[str, Any]) -> None:
            self.progress_bar.setValue(100)
            self._set_status("Adli temizlik başarıyla tamamlandı.", "success")
            self.console.append_log("Tüm seçili adli artefaktlar yok edildi.", "OK")
            self.btn_start.setEnabled(True)
            self.cleanup_finished.emit(data)

        def _on_error(err_msg: str) -> None:
            self.progress_bar.setValue(0)
            self._set_status(f"Hata: {err_msg}", "danger")
            self.console.append_log(f"Temizlik başarısız oldu: {err_msg}", "ERROR")
            self.btn_start.setEnabled(True)

        AsyncDaemonWorker(
            client=self.client,
            action="clean_forensics",
            params={"targets": targets},
            timeout=120.0,
            on_success=_on_success,
            on_error=_on_error,
        ).start()
