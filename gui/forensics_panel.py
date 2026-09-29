"""AnonVoid - Adli Temizlik Paneli (Forensics Dashboard).

Bu modül; kullanıcının shell geçmişi, sistem günlükleri, önbellekler, bellek,
SSD TRIM ve boş alan sıfırlama modüllerini seçebileceği modern bir seçim matrisi,
adım adım ilerleme çubuğu (%0-100) ve anlık log konsolunu barındırır.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Optional

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.daemon_client import AsyncDaemonWorker, DaemonClient
from gui.widgets import LogConsoleWidget


class ForensicsPanel(QWidget):
    """Adli iz temizleme seçim matrisi ve ilerleme paneli."""

    cleanup_started = pyqtSignal()
    cleanup_finished = pyqtSignal(dict)

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
        title = QLabel("Adli Bilişim ve Dijital İz Temizliği (Anti-Forensics)", self)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #ffffff;")
        header_layout.addWidget(title)

        desc = QLabel(
            "Disk blokları, RAM, terminal geçmişi ve sistem günlüklerindeki adli kalıntıları yok edin.",
            self,
        )
        desc.setStyleSheet("font-size: 12px; color: #888888;")
        header_layout.addWidget(desc)
        main_layout.addLayout(header_layout)

        # Seçim Matrisi (Grid Şeklinde CheckBox Kartları)
        matrix_group = QGroupBox("Temizlik Modülleri Seçim Matrisi", self)
        matrix_group.setStyleSheet("font-weight: bold; font-size: 13px;")
        matrix_layout = QGridLayout(matrix_group)
        matrix_layout.setContentsMargins(16, 16, 16, 16)
        matrix_layout.setSpacing(14)

        # 1. Shell ve Komut Geçmişi
        self.chk_shell = QCheckBox("Shell & Komut Geçmişi (.bash, .zsh, python, mysql shred)", self)
        self.chk_shell.setChecked(True)
        matrix_layout.addWidget(self.chk_shell, 0, 0)

        # 2. Sistem Günlükleri
        self.chk_journal = QCheckBox("Sistem Günlükleri (journald vacuum, logrotate simülasyonu)", self)
        self.chk_journal.setChecked(True)
        matrix_layout.addWidget(self.chk_journal, 0, 1)

        # 3. Küçük Resimler ve MRU
        self.chk_cache = QCheckBox("Önbellek & MRU (Küçük resimler, recently-used.xbel, trash)", self)
        self.chk_cache.setChecked(True)
        matrix_layout.addWidget(self.chk_cache, 1, 0)

        # 4. RAM ve Takas Alanı
        self.chk_ram = QCheckBox("RAM & Takas Alanı (drop_caches, compact_memory, swapoff)", self)
        self.chk_ram.setChecked(True)
        matrix_layout.addWidget(self.chk_ram, 1, 1)

        # 5. SSD TRIM ve FTL Yönetimi
        self.chk_trim = QCheckBox("Modern Depolama & SSD TRIM (fstrim -av flash hücre sıfırlama)", self)
        self.chk_trim.setChecked(True)
        matrix_layout.addWidget(self.chk_trim, 2, 0)

        # 6. Paket Yöneticisi ve Sandbox
        self.chk_pkg = QCheckBox("Paket Yöneticisi & Sandbox (APT, Pacman, Flatpak, Snap)", self)
        self.chk_pkg.setChecked(True)
        matrix_layout.addWidget(self.chk_pkg, 2, 1)

        # 7. İsteğe Bağlı: Boş Alan Sıfırlama
        self.chk_zero_space = QCheckBox("Boş Alan Sıfırlama (Unallocated space zeroing - Uzun sürer)", self)
        self.chk_zero_space.setChecked(False)
        matrix_layout.addWidget(self.chk_zero_space, 3, 0)

        # 8. İsteğe Bağlı: Swap Alanını Sıfırdan Doldur
        self.chk_swap_zero = QCheckBox("Swap Alanını Urandom ile Doldur (Derin temizlik)", self)
        self.chk_swap_zero.setChecked(False)
        matrix_layout.addWidget(self.chk_swap_zero, 3, 1)

        main_layout.addWidget(matrix_group)

        # Butonlar Satırı
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(12)

        self.btn_select_all = QPushButton("Tümünü Seç", self)
        self.btn_select_all.clicked.connect(self._select_all)
        btn_layout.addWidget(self.btn_select_all)

        self.btn_clear_selection = QPushButton("Seçimi Temizle", self)
        self.btn_clear_selection.clicked.connect(self._clear_selection)
        btn_layout.addWidget(self.btn_clear_selection)

        btn_layout.addStretch()

        self.btn_start = QPushButton("🧹 ADLİ TEMİZLİĞİ BAŞLAT", self)
        self.btn_start.setObjectName("primaryButton")
        self.btn_start.setMinimumHeight(40)
        self.btn_start.setMinimumWidth(220)
        self.btn_start.clicked.connect(self.start_cleanup)
        btn_layout.addWidget(self.btn_start)

        main_layout.addLayout(btn_layout)

        # İlerleme Çubuğu ve Durum
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(4)
        self.status_label = QLabel("Hazır: Temizlik modüllerini seçip başlatın.", self)
        self.status_label.setStyleSheet("font-size: 12px; color: #888888;")
        progress_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)
        main_layout.addLayout(progress_layout)

        # Canlı Terminal Günlüğü
        log_label = QLabel("Adli Temizlik İşlem Günlüğü (Console Log):", self)
        log_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        main_layout.addWidget(log_label)

        self.console = LogConsoleWidget(self)
        self.console.setMinimumHeight(140)
        main_layout.addWidget(self.console)

    def _select_all(self) -> None:
        """Tüm modülleri seçer."""
        for chk in [
            self.chk_shell,
            self.chk_journal,
            self.chk_cache,
            self.chk_ram,
            self.chk_trim,
            self.chk_pkg,
            self.chk_zero_space,
            self.chk_swap_zero,
        ]:
            chk.setChecked(True)

    def _clear_selection(self) -> None:
        """Tüm seçimleri kaldırır."""
        for chk in [
            self.chk_shell,
            self.chk_journal,
            self.chk_cache,
            self.chk_ram,
            self.chk_trim,
            self.chk_pkg,
            self.chk_zero_space,
            self.chk_swap_zero,
        ]:
            chk.setChecked(False)

    def get_selected_targets(self) -> Dict[str, bool]:
        """Kullanıcının seçtiği modülleri sözlük olarak döner."""
        return {
            "clean_shell_history": self.chk_shell.isChecked(),
            "clean_journal_logs": self.chk_journal.isChecked(),
            "clean_text_logs": self.chk_journal.isChecked(),
            "clean_thumbnails": self.chk_cache.isChecked(),
            "clean_mru_cache": self.chk_cache.isChecked(),
            "clean_trash": self.chk_cache.isChecked(),
            "clean_memory_caches": self.chk_ram.isChecked(),
            "clean_swap": self.chk_swap_zero.isChecked(),
            "ssd_trim": self.chk_trim.isChecked(),
            "clean_package_cache": self.chk_pkg.isChecked(),
            "free_space_zeroing": self.chk_zero_space.isChecked(),
        }

    def start_cleanup(self) -> None:
        """Temizlik sürecini GUI'yi kilitlemeden asenkron başlatır."""
        targets = self.get_selected_targets()
        self.btn_start.setEnabled(False)
        self.progress_bar.setValue(10)
        self.status_label.setText("Adli temizlik yürütülüyor...")
        self.console.append_log("Adli temizlik talebi root daemon servisine iletildi...", "INFO")
        self.cleanup_started.emit()

        def _on_success(data: Dict[str, Any]) -> None:
            self.progress_bar.setValue(100)
            self.status_label.setText("Adli temizlik başarıyla tamamlandı!")
            self.console.append_log("Tüm seçili adli artefaktlar başarıyla yok edildi.", "INFO")
            self.btn_start.setEnabled(True)
            self.cleanup_finished.emit(data)

        def _on_error(err_msg: str) -> None:
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Hata: {err_msg}")
            self.console.append_log(f"Temizlik başarısız oldu: {err_msg}", "ERROR")
            self.btn_start.setEnabled(True)

        worker = AsyncDaemonWorker(
            client=self.client,
            action="clean_forensics",
            params={"targets": targets},
            timeout=120.0,
            on_success=_on_success,
            on_error=_on_error,
        )
        worker.start()
