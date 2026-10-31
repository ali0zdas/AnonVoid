"""AnonVoid - Faz 1 Çekirdek ve IPC Birim Testleri.

Bu dosya; config doğrulamaları, SO_PEERCRED yetki modelleri, katı komut beyaz listesi
ve güvenli dosya okuma/yazma mekanizmalarını test eder.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Proje kök dizinini sys.path'e ekle
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Kasıtlı olarak var olmayan soket yolu. AGENTS.md gereği herkese yazılabilir
# /tmp kullanılmaz; test yalnızca "bağlantı kurulamadı" yolunu sınar.
_RUNTIME_DIR = os.environ.get("XDG_RUNTIME_DIR") or os.path.join(
    os.path.expanduser("~"), ".cache"
)
MISSING_SOCKET_PATH = os.path.join(_RUNTIME_DIR, "anonvoid-test-yok-boyle-bir-soket.sock")

from core.config import (
    DEFAULT_CONFIG,
    cfg_bool,
    cfg_interface_name,
    cfg_port,
    cfg_uid,
    deep_merge,
    safe_load_config,
    safe_save_config,
    validate_full_config,
)
from core.daemon import RootDaemon
from core.daemon_client import (
    AsyncDaemonWorker,
    DaemonClient,
    DaemonConnectionError,
    DaemonResponseError,
)
from core.netns_sandbox import run_in_tor_capsule
from core.usb_guard import USBKillSwitchMonitor, list_usb_devices


class TestConfigModule(unittest.TestCase):
    """core/config.py birim testleri."""

    def test_cfg_port_valid(self):
        """Geçerli portların doğrulanmasını test eder."""
        self.assertEqual(cfg_port(80), 80)
        self.assertEqual(cfg_port("9050"), 9050)
        self.assertEqual(cfg_port(65535), 65535)
        self.assertEqual(cfg_port(1), 1)

    def test_cfg_port_invalid(self):
        """Geçersiz portların tespit edilip reddedilmesini test eder."""
        with self.assertRaises(ValueError):
            cfg_port(0)
        with self.assertRaises(ValueError):
            cfg_port(65536)
        with self.assertRaises(ValueError):
            cfg_port(-1)
        with self.assertRaises(ValueError):
            cfg_port("abc")
        with self.assertRaises(ValueError):
            cfg_port("9050; rm -rf")

        # Varsayılan değer testi
        self.assertEqual(cfg_port("gecersiz", default=9040), 9040)
        self.assertEqual(cfg_port(-50, default=5300), 5300)

    def test_cfg_uid_valid(self):
        """Geçerli kullanıcı kimliklerinin doğrulanmasını test eder."""
        self.assertEqual(cfg_uid(0), 0)
        self.assertEqual(cfg_uid(1000), 1000)
        self.assertEqual(cfg_uid("1001"), 1001)

    def test_cfg_uid_invalid(self):
        """Geçersiz UID değerlerinin reddedilmesini test eder."""
        with self.assertRaises(ValueError):
            cfg_uid(-1)
        with self.assertRaises(ValueError):
            cfg_uid("root")
        with self.assertRaises(ValueError):
            cfg_uid("1000; id")
        self.assertEqual(cfg_uid("invalid", default=1000), 1000)

    def test_cfg_bool(self):
        """Boole dönüştürücü ve doğrulayıcı testleri."""
        self.assertTrue(cfg_bool(True))
        self.assertTrue(cfg_bool("true"))
        self.assertTrue(cfg_bool("1"))
        self.assertTrue(cfg_bool("evet"))
        self.assertTrue(cfg_bool("aktif"))
        self.assertFalse(cfg_bool(False))
        self.assertFalse(cfg_bool("false"))
        self.assertFalse(cfg_bool("0"))
        self.assertFalse(cfg_bool("hayır"))
        self.assertFalse(cfg_bool("pasif"))

    def test_cfg_interface_name(self):
        """Ağ arayüzü isim kontrollerini test eder."""
        self.assertEqual(cfg_interface_name("eth0"), "eth0")
        self.assertEqual(cfg_interface_name("wlan0"), "wlan0")
        self.assertEqual(cfg_interface_name("tun0"), "tun0")
        with self.assertRaises(ValueError):
            cfg_interface_name("eth0; rm -rf")
        with self.assertRaises(ValueError):
            cfg_interface_name("a" * 20)  # 16 karakterden uzun

    def test_deep_merge(self):
        """Derin birleştirme (deep merge) mantığını test eder."""
        base = {"a": 1, "b": {"c": 2, "d": 3}}
        override = {"b": {"d": 42, "e": 5}, "f": 6}
        merged = deep_merge(base, override)
        self.assertEqual(merged["a"], 1)
        self.assertEqual(merged["b"]["c"], 2)
        self.assertEqual(merged["b"]["d"], 42)
        self.assertEqual(merged["b"]["e"], 5)
        self.assertEqual(merged["f"], 6)

    def test_safe_save_and_load_config(self):
        """Güvenli dosya yazma ve okuma döngüsünü test eder."""
        with tempfile.TemporaryDirectory() as tmpdir:
            conf_path = os.path.join(tmpdir, "config.json")
            test_data = {"network": {"tor_socks_port": 9150}}
            self.assertTrue(safe_save_config(conf_path, test_data))
            loaded = safe_load_config(conf_path)
            self.assertEqual(loaded["network"]["tor_socks_port"], 9150)
            self.assertEqual(loaded["network"]["tor_trans_port"], 9040)  # Varsayılandan geldi

    def test_validate_full_config_path_traversal_rejection(self):
        """validate_full_config'in path traversal ve yetkisiz soket yollarını reddettiğini doğrular."""
        traversal_inputs = [
            "/run/../tmp/evil.sock",
            "/run/anonvoid/../../etc/passwd",
            "/tmp/evil.sock",
            "/run/evil\x00.sock",
            "/var/run/anonvoid.sock",
        ]
        default_sock = DEFAULT_CONFIG["daemon"]["socket_path"]
        for bad_path in traversal_inputs:
            cfg = {"daemon": {"socket_path": bad_path}}
            validated = validate_full_config(cfg)
            self.assertEqual(
                validated["daemon"]["socket_path"],
                default_sock,
                f"Güvensiz soket yolu engellenemedi: {bad_path}",
            )

        # Geçerli /run yolu kabul edilmeli
        valid_cfg = {"daemon": {"socket_path": "/run/anonvoid/custom.sock"}}
        self.assertEqual(
            validate_full_config(valid_cfg)["daemon"]["socket_path"],
            "/run/anonvoid/custom.sock",
        )

    def test_validate_full_config_new_fields(self):
        """Yeni yapılandırma alanlarının (use_bridges, exclude_five_eyes, usb_killswitch_enabled) doğrulandığını test eder."""
        raw_cfg = {
            "network": {
                "use_bridges": "true",
                "exclude_five_eyes": 1,
                "bridge_type": "snowflake",
            },
            "security": {
                "usb_killswitch_enabled": "evet",
                "usb_authorized_device_id": "1234:abcd",
            },
        }
        validated = validate_full_config(raw_cfg)
        self.assertTrue(validated["network"]["use_bridges"])
        self.assertTrue(validated["network"]["exclude_five_eyes"])
        self.assertEqual(validated["network"]["bridge_type"], "snowflake")
        self.assertTrue(validated["security"]["usb_killswitch_enabled"])
        self.assertEqual(validated["security"]["usb_authorized_device_id"], "1234:abcd")


class TestDaemonModule(unittest.TestCase):
    """core/daemon.py birim testleri."""

    def setUp(self):
        self.daemon = RootDaemon()

    def test_whitelisted_commands(self):
        """Katı beyaz listedeki tüm komutların kabul edildiğini test eder."""
        whitelisted_actions = [
            "ping",
            "status",
            "connect",
            "disconnect",
            "new_circuit",
            "clean_forensics",
            "leak_test",
            "panic",
        ]
        for action in whitelisted_actions:
            payload = json.dumps({"action": action, "req_id": "test-123"}).encode("utf-8")
            resp = self.daemon._dispatch_request(payload, uid=0, gid=0)
            self.assertEqual(resp["status"], "ok", f"Eylem başarısız: {action}")
            self.assertEqual(resp["action"], action)

    def test_unauthorized_command_rejection(self):
        """Beyaz liste dışındaki enjeksiyon veya geçersiz komutların reddedildiğini test eder."""
        malicious_payloads = [
            {"action": "rm -rf /"},
            {"action": "exec"},
            {"action": "eval"},
            {"action": "shell"},
            {"action": "iptables -F"},
            {"action": "systemctl stop"},
            {"action": "bilinmeyen_aksiyon"},
        ]
        for item in malicious_payloads:
            payload = json.dumps(item).encode("utf-8")
            resp = self.daemon._dispatch_request(payload, uid=0, gid=0)
            self.assertEqual(resp["status"], "error")
            self.assertIn("Yetkilendirilmemiş", resp["error"])

    def test_payload_size_limit(self):
        """Aşırı büyük yüklerin (DoS önleme) reddedildiğini test eder."""
        huge_payload = b"A" * 70000
        resp = self.daemon._dispatch_request(huge_payload, uid=0, gid=0)
        self.assertEqual(resp["status"], "error")
        self.assertIn("bayt sınırını aştı", resp["error"])

    def test_startup_heal_safe_execution(self):
        """_startup_heal fonksiyonunun hatasız çalıştığını test eder."""
        try:
            self.daemon.startup_heal()
        except Exception as err:
            self.fail(f"startup_heal beklenmedik hata fırlattı: {err}")


def _pump_gui_events(join_fn, timeout: float) -> None:
    """Varsa Qt olay döngüsünü döndürerek kuyruklanmış geri çağrıları çalıştırır.

    PyQt6 kurulu değilse veya QApplication yoksa doğrudan çalışan geri
    çağrılar için ek iş gerekmez.
    """
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        join_fn(timeout=timeout)
        return

    app = QApplication.instance()
    if app is None:
        join_fn(timeout=timeout)
        return

    deadline = time.time() + timeout
    join_fn(timeout=timeout)
    while time.time() < deadline:
        app.processEvents()
        time.sleep(0.01)


class TestDaemonClientModule(unittest.TestCase):
    """core/daemon_client.py birim testleri."""

    def test_client_missing_socket(self):
        """Var olmayan soket için DaemonConnectionError fırlatılmasını test eder."""
        client = DaemonClient(socket_path=MISSING_SOCKET_PATH)
        with self.assertRaises(DaemonConnectionError):
            client.send_request("ping")

    def test_async_worker(self):
        """Asenkron worker iş parçacığı hata yakalama ve callback döngüsünü test eder."""
        client = DaemonClient(socket_path=MISSING_SOCKET_PATH)
        error_captured = []
        finished_flag = []

        worker = AsyncDaemonWorker(
            client=client,
            action="ping",
            on_error=lambda err: error_captured.append(err),
            on_finished=lambda: finished_flag.append(True),
        )
        worker.start()
        worker.join(timeout=3.0)

        # Qt bağlamında geri çağrılar GUI iş parçacığına kuyruklanır; olay
        # döngüsü hiç dönmüyorsa kuyruk boşalana kadar beklenmelidir.
        _pump_gui_events(worker.join, timeout=3.0)

        self.assertTrue(len(error_captured) > 0)
        self.assertTrue(len(finished_flag) > 0)

    def test_async_worker_calls_callbacks_on_gui_thread(self):
        """Geri çağrıların iş parçacığında değil, GUI iş parçacığında çalıştığını doğrular.

        Bu, Qt thread-affinity kuralının ihlali ve buna bağlı uygulama
        çökmelerini (StatusRingWidget uyarıları, segmentation fault) önler.
        """
        try:
            from PyQt6.QtCore import QThread
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            self.skipTest("PyQt6 kurulu değil.")

        app = QApplication.instance() or QApplication([])
        gui_thread = QThread.currentThread()

        client = DaemonClient(socket_path=MISSING_SOCKET_PATH)
        seen_threads = []

        worker = AsyncDaemonWorker(
            client=client,
            action="ping",
            on_error=lambda err: seen_threads.append(QThread.currentThread()),
            on_finished=lambda: seen_threads.append(QThread.currentThread()),
        )
        worker.start()
        worker.join(timeout=3.0)

        deadline = time.time() + 5.0
        while len(seen_threads) < 2 and time.time() < deadline:
            app.processEvents()
            time.sleep(0.01)

        self.assertEqual(len(seen_threads), 2, "Geri çağrılar kuyruklanmadı.")
        for thread in seen_threads:
            # PyQt her çağrıda yeni bir sarmalayıcı üretebilir; aynı iş parçacığı
            # kimliği için altta yatan C++ nesnesi karşılaştırılır.
            self.assertEqual(
                thread,
                gui_thread,
                "Geri çağrı arka plan iş parçacığında çalıştı; Qt bileşenlerine "
                "farklı iş parçacığından erişilmiş olur.",
            )


class TestUSBGuardModule(unittest.TestCase):
    """core/usb_guard.py birim testleri."""

    def test_usb_killswitch_monitor_trigger_on_removal(self):
        """Yetkili USB aygıtı sistemden çıkarıldığında on_trigger geri çağrısının çalıştığını test eder."""
        trigger_called = threading.Event()

        def _on_trigger():
            trigger_called.set()

        monitor = USBKillSwitchMonitor(
            authorized_device_id="0781:5583",
            on_trigger=_on_trigger,
            poll_interval=0.2,
            trigger_on_removal=True,
            trigger_on_unauthorized_insert=False,
        )

        sample_devices = [
            {"device_id": "0781:5583", "vendor_id": "0781", "product_id": "5583"}
        ]

        # Başlangıçta aygıt takılı, ardından çıkarılmış simülasyonu (boş liste)
        def _mock_list_devices(path=None):
            if not trigger_called.is_set() and monitor._thread is None:
                return sample_devices
            return []

        with mock.patch("core.usb_guard.list_usb_devices", side_effect=_mock_list_devices):
            started = monitor.start()
            self.assertTrue(started)
            triggered = trigger_called.wait(timeout=2.0)
            monitor.stop()

        self.assertTrue(triggered, "USB çekilme panik tetiği ateşlenmedi!")

    def test_list_usb_devices_missing_dir(self):
        """Var olmayan sysfs yolunda boş liste döndüğünü test eder."""
        devs = list_usb_devices("/tmp/yok_boyle_sysfs_usb_yolu")
        self.assertEqual(devs, [])


class TestNetNSSandboxModule(unittest.TestCase):
    """core/netns_sandbox.py birim testleri."""

    @mock.patch("core.netns_sandbox.subprocess.run")
    @mock.patch("core.netns_sandbox.is_port_open", return_value=True)
    def test_run_in_tor_capsule_with_torsocks(self, mock_port, mock_run):
        """torsocks ikili dosyası mevcutken komutun torsocks ile sarmalandığını test eder."""
        mock_run.return_value.returncode = 0

        with mock.patch("shutil.which", return_value="/usr/bin/torsocks"):
            ret = run_in_tor_capsule(
                ["curl", "https://check.torproject.org"],
                socks_port=9050,
            )

        self.assertEqual(ret, 0)
        self.assertTrue(mock_run.called)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(
            called_cmd,
            ["/usr/bin/torsocks", "-P", "9050", "curl", "https://check.torproject.org"],
        )
        called_env = mock_run.call_args[1]["env"]
        self.assertEqual(called_env.get("ALL_PROXY"), "socks5h://127.0.0.1:9050")

    @mock.patch("core.netns_sandbox.subprocess.run")
    @mock.patch("core.netns_sandbox.is_port_open", return_value=True)
    def test_run_in_tor_capsule_fallback_env(self, mock_port, mock_run):
        """torsocks yokken ortam değişkenleriyle doğrudan çalıştırıldığını test eder."""
        mock_run.return_value.returncode = 0

        with mock.patch("shutil.which", return_value=None):
            ret = run_in_tor_capsule(
                ["curl", "https://check.torproject.org"],
                socks_port=9050,
            )

        self.assertEqual(ret, 0)
        self.assertTrue(mock_run.called)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd, ["curl", "https://check.torproject.org"])
        called_env = mock_run.call_args[1]["env"]
        self.assertEqual(called_env.get("ALL_PROXY"), "socks5h://127.0.0.1:9050")
        self.assertEqual(called_env.get("HTTP_PROXY"), "socks5h://127.0.0.1:9050")


if __name__ == "__main__":
    unittest.main()
