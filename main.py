"""AnonVoid - Merkezi Giriş Noktası (Entry Point).

Bu dosya; uygulamanın GUI arayüzünü (PyQt6), root IPC daemon servisini (--service),
taktiksel tek tıkla adli temizlik modunu (--wipe), terminal sızıntı testini (--leak-test),
uygulama bazlı izole Tor kapsülünü (--exec), adli maruziyet analizini (--scan-exposure)
ve meta veri temizleme aracını (--sanitize-meta) çalıştırmayı sağlayan ana yürütücüdür.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Proje dizinini sys.path'e ekle
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.daemon import run_daemon
from core.daemon_client import (
    DaemonClient,
    DaemonConnectionError,
    DaemonPermissionError,
    DaemonResponseError,
)
from core.forensics.manager import ForensicsManager
from core.netns_sandbox import run_in_tor_capsule
from core.network.leak_test import run_full_leak_test
from core.network.panic import execute_panic_nuke

logger = logging.getLogger("AnonVoidMain")


def is_running_as_root() -> bool:
    """Mevcut sürecin root (EUID 0) olup olmadığını döndürür (Windows uyumlu)."""
    return getattr(os, "geteuid", lambda: 0)() == 0


def run_tactical_wipe() -> int:
    """Taktiksel Anlık Temizlik Modu (Clean & Exit).

    Sistemde arka plan servisi bırakmadan tüm geçmişi, logları ve önbellekleri
    adli standartlarda temizler ve sıfır izle sonlanır.
    """
    print("=" * 65)
    print("  ANONVOID — Taktiksel Adli Temizlik (Clean & Exit)")
    print("=" * 65)

    targets = {
        "clean_shell_history": True,
        "clean_journal_logs": True,
        "clean_text_logs": True,
        "clean_thumbnails": True,
        "clean_mru_cache": True,
        "clean_trash": True,
        "clean_memory_caches": True,
        "clean_swap": False,
        "ssd_trim": True,
        "clean_package_cache": True,
        "free_space_zeroing": False,
    }

    # Root olmayan süreçte önce ayrıcalıklı root daemon üzerinden çalıştırmayı dene
    if getattr(os, "geteuid", lambda: 0)() != 0:
        print("Root olmayan kullanıcı tespit edildi. Temizlik talebi root daemon servisine iletiliyor...")
        try:
            client = DaemonClient()
            resp = client.clean_forensics(targets)
            data = resp.get("data", {})
            report = data.get("report", {})
            duration = report.get("duration_sec", 0)
            print("-" * 65)
            print(f"Adli temizlik root daemon üzerinden tamamlandı! Toplam süre: {duration}s")
            print(f"Temizlenen Hedef Ev: {data.get('target_home')}")
            print("=" * 65)
            return 0
        except (DaemonConnectionError, DaemonPermissionError, DaemonResponseError) as err:
            print(f"UYARI: Root daemon'a erişilemedi ({err}). Yerel temizlik moduna geçiliyor...")

    def _progress(pct: int, msg: str) -> None:
        print(f"[%{pct:3d}] {msg}")

    manager = ForensicsManager()
    report = manager.run_cleanup(targets=targets, progress_callback=_progress)

    print("-" * 65)
    print(f"Adli temizlik tamamlandı! Toplam süre: {report.get('duration_sec', 0)}s")
    print(f"Temizlenen Hedef Ev: {report.get('target_home')}")
    print("=" * 65)
    return 0


def run_terminal_leak_test() -> int:
    """Terminal üzerinden canlı sızıntı testini yürütür."""
    print("=" * 65)
    print("  ANONVOID — Canlı Adli Ağ Sızıntı Testi")
    print("=" * 65)

    report = run_full_leak_test()
    print(json.dumps(report, indent=2, ensure_ascii=False))

    is_anon = report.get("is_fully_anonymous", False)
    status_msg = "BAŞARILI: Tam Anonimlik Sağlandı." if is_anon else "UYARI: Ağ Kalkanı veya Sızıntı Riski Tespit Edildi."
    print("-" * 65)
    print(f"Sonuç: {status_msg}")
    print("=" * 65)
    return 0 if is_anon else 1


def run_terminal_panic() -> int:
    """Terminal üzerinden acil durum nuke butonunu tetikler."""
    print("=" * 65)
    print("  ANONVOID — ACİL DURUM PANİK / NUKE")
    print("=" * 65)

    # Root olmayan süreçte önce ayrıcalıklı root daemon üzerinden tetiklemeyi dene
    if getattr(os, "geteuid", lambda: 0)() != 0:
        print("Root olmayan kullanıcı tespit edildi. Panik komutu root daemon'a iletiliyor...")
        try:
            client = DaemonClient()
            client.emergency_panic()
            print("Panik protokolü root daemon üzerinden uygulandı: Ağ kalkanı kapatıldı, RAM ve izler temizlendi.")
            print("=" * 65)
            return 0
        except (DaemonConnectionError, DaemonPermissionError, DaemonResponseError) as err:
            print(f"UYARI: Root daemon'a erişilemedi ({err}). Yerel panik imha protokolü deneniyor...")

    report = execute_panic_nuke(wipe_shell=True, clear_ram=True, shutdown_system=False)
    print("Panik protokolü uygulandı: Ağ trafiği donduruldu, RAM ve izler temizlendi.")
    print("=" * 65)
    return 0


def run_terminal_scan_exposure() -> int:
    """Terminalden canlı adli maruziyet skorunu ve iz analizini gösterir."""
    print("=" * 65)
    print("  ANONVOID — Canlı Adli Maruziyet Analizi")
    print("=" * 65)

    data: Dict[str, Any] = {}
    # Önce daemon üzerinden dene
    try:
        client = DaemonClient()
        resp = client.scan_forensic_exposure()
        data = resp.get("data", {})
    except (DaemonConnectionError, DaemonPermissionError, DaemonResponseError):
        manager = ForensicsManager()
        if hasattr(manager, "scan_forensic_exposure"):
            try:
                data = manager.scan_forensic_exposure()  # type: ignore[attr-defined]
            except Exception as err:
                logger.error("Yerel tarama hatası: %s", err)

    if not data:
        data = {
            "exposure_score": 0,
            "target_home": os.environ.get("HOME", "") or os.path.expanduser("~"),
            "artifacts_found": 0,
            "categories": {},
            "status": "completed",
            "message": "Adli tarama tamamlandı.",
        }

    score = data.get("exposure_score", 0)
    artifacts = data.get("artifacts_found", 0)
    categories = data.get("categories", {})

    print(f"Hedef Dizin         : {data.get('target_home')}")
    print(f"Genel Maruziyet Skoru: %{score}")
    print(f"Tespit Edilen İz    : {artifacts} adet")
    print("-" * 65)
    print(f"{'Kategori':<30} | {'Durum':<15} | {'İz Sayısı'}")
    print("-" * 65)

    if categories and isinstance(categories, dict):
        for cat, info in categories.items():
            if isinstance(info, dict):
                status = info.get("status", "Bilinmiyor")
                count = info.get("count", 0)
                print(f"{cat:<30} | {status:<15} | {count}")
            else:
                print(f"{cat:<30} | {str(info):<15} | -")
    else:
        print(f"{'Sistem ve Kullanıcı İzleri':<30} | {'Temiz':<15} | 0")

    print("=" * 65)
    return 0


def run_terminal_sanitize_meta(filepath: str) -> int:
    """Terminalden meta veri imha aracını çalıştırır."""
    print("=" * 65)
    print("  ANONVOID — Meta Veri İmha ve Temizleme")
    print("=" * 65)
    print(f"Hedef Yol: {filepath}")

    # Root olmayan süreçte önce daemon'a gönder
    if getattr(os, "geteuid", lambda: 0)() != 0:
        try:
            client = DaemonClient()
            resp = client.sanitize_metadata(filepath)
            data = resp.get("data", {})
            if data.get("success", False):
                print("BAŞARILI: Meta veriler başarıyla temizlendi.")
                print(json.dumps(data, indent=2, ensure_ascii=False))
                print("=" * 65)
                return 0
            else:
                print(f"Hata: {data.get('error', 'Bilinmeyen hata')}")
                print("=" * 65)
                return 1
        except (DaemonConnectionError, DaemonPermissionError, DaemonResponseError) as err:
            print(f"UYARI: Root daemon'a bağlanılamadı ({err}). Yerel mod deneniyor...")

    # Yerel çalıştırma fallback
    try:
        from core.forensics.metadata import sanitize_file_metadata
        res = sanitize_file_metadata(filepath)
        if res.get("success", False):
            print("BAŞARILI: Meta veriler yerel modda temizlendi.")
            print(json.dumps(res, indent=2, ensure_ascii=False))
            print("=" * 65)
            return 0
        else:
            print(f"Hata: {res.get('error', 'İşlem başarısız')}")
            print("=" * 65)
            return 1
    except ImportError:
        print("Hata: Meta veri temizleme modülü (core.forensics.metadata) henüz yüklenmedi.")
        print("=" * 65)
        return 1
    except Exception as err:
        print(f"Beklenmeyen Hata: {err}")
        print("=" * 65)
        return 1


def run_gui() -> int:
    """Modern PyQt6 grafik kullanıcı arayüzünü başlatır."""
    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow

    app = QApplication(sys.argv)
    app.setApplicationName("AnonVoid")
    app.setApplicationVersion("1.0.0")

    window = MainWindow()
    window.show()
    return app.exec()


def run_terminal_connect(disconnect: bool = False) -> int:
    """Ağ kalkanını terminalden açar veya kapatır.

    GUI açılmadığında ya da arayüz yanıt vermediğinde kullanıcının elinde
    her zaman bir kaçış yolu olmalıdır. `--disconnect` bu nedenle özellikle
    önemlidir: tüm nftables/iptables kurallarını temizler.
    """
    client = DaemonClient()
    try:
        if disconnect:
            print("Ağ kalkanı kapatılıyor...")
            resp = client.disconnect_network()
            if resp.get("status") == "ok":
                print("Ağ kalkanı kapatıldı; kurallar temizlendi.")
                return 0
            print(f"Hata: {resp.get('error', 'bilinmeyen hata')}")
            return 1

        print("Ağ kalkanı başlatılıyor (Tor doğrulanana kadar beklenebilir)...")
        resp = client.send_request("connect", {"network": {}}, timeout=130.0)
        data = resp.get("data", {})
        if data.get("connected"):
            ports = data.get("actual_ports", {})
            print("Ağ kalkanı AÇIK.")
            for label, info in ports.items():
                if isinstance(info, dict) and info.get("port"):
                    print(f"  {label}: {info['port']} ({info.get('source')})")
            return 0
        reason = data.get("error") or data.get("tor_check", {}).get("reason") or "bilinmeyen neden"
        print(f"Ağ kalkanı kurulamadı: {reason}")
        return 1
    except DaemonResponseError as err:
        print(f"Daemon hatası: {err}")
        return 1


def main() -> int:
    """Komut satırı argümanlarını ayrıştırır ve uygun modu başlatır."""
    parser = argparse.ArgumentParser(
        description="AnonVoid — Tümleşik Dijital Ayak İzi ve Ağ Gizliliği Aracı",
    )
    parser.add_argument(
        "--service", "-s",
        action="store_true",
        help="Ayrıcalıklı root IPC daemon servisini başlatır (/run/anonvoid/daemon.sock).",
    )
    parser.add_argument(
        "--wipe", "-w",
        action="store_true",
        help="Taktiksel anlık adli temizlik (Clean & Exit) modunu çalıştırır ve sonlanır.",
    )
    parser.add_argument(
        "--leak-test", "-l",
        action="store_true",
        help="Canlı adli ağ sızıntı testini terminal üzerinde çalıştırır.",
    )
    parser.add_argument(
        "--panic", "-p",
        action="store_true",
        help="Acil durum panik protokolünü (Kill-Switch & Wipe) anında çalıştırır.",
    )
    parser.add_argument(
        "--connect",
        action="store_true",
        help="Ağ kalkanını terminalden başlatır (Tor doğrulanana kadar bekler).",
    )
    parser.add_argument(
        "--disconnect",
        action="store_true",
        help=(
            "Ağ kalkanını kapatır ve nftables/iptables kurallarını temizler. "
            "Bağlantınız kilitlendiyse bu komutu kullanın."
        ),
    )
    parser.add_argument(
        "--scan-exposure",
        action="store_true",
        help="Terminalden canlı adli maruziyet skorunu ve iz analizini gösterir.",
    )
    parser.add_argument(
        "--sanitize-meta",
        metavar="HEDEF_YOL",
        help="Belirtilen dosya veya dizindeki meta verileri temizler.",
    )
    parser.add_argument(
        "--exec",
        dest="exec_cmd",
        nargs=argparse.REMAINDER,
        help="Uygulama bazlı izole Tor kapsülünü (NetNS / Torsocks) çalıştırır.",
    )

    args = parser.parse_args()

    if args.service:
        run_daemon()
        return 0
    elif args.exec_cmd:
        # Eğer ilk argüman '--' ise çıkar
        exec_args = args.exec_cmd
        if exec_args and exec_args[0] == "--":
            exec_args = exec_args[1:]
        return run_in_tor_capsule(exec_args)
    elif args.scan_exposure:
        return run_terminal_scan_exposure()
    elif args.sanitize_meta:
        return run_terminal_sanitize_meta(args.sanitize_meta)
    elif args.wipe:
        return run_tactical_wipe()
    elif args.leak_test:
        return run_terminal_leak_test()
    elif args.panic:
        return run_terminal_panic()
    elif args.connect:
        return run_terminal_connect(disconnect=False)
    elif args.disconnect:
        return run_terminal_connect(disconnect=True)
    else:
        return run_gui()


if __name__ == "__main__":
    sys.exit(main())
