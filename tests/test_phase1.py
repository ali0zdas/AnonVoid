"""AnonVoid - Faz 1 Çekirdek ve IPC Birim Testleri.

Bu dosya; config doğrulamaları, SO_PEERCRED yetki modelleri, katı komut beyaz listesi
ve güvenli dosya okuma/yazma mekanizmalarını test eder.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

# Proje kök dizinini sys.path'e ekle
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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


class TestDaemonClientModule(unittest.TestCase):
    """core/daemon_client.py birim testleri."""

    def test_client_missing_socket(self):
        """Var olmayan soket için DaemonConnectionError fırlatılmasını test eder."""
        client = DaemonClient(socket_path="/tmp/non_existent_fp_cleaner_socket.sock")
        with self.assertRaises(DaemonConnectionError):
            client.send_request("ping")

    def test_async_worker(self):
        """Asenkron worker iş parçacığı hata yakalama ve callback döngüsünü test eder."""
        client = DaemonClient(socket_path="/tmp/non_existent_fp_cleaner_socket.sock")
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

        self.assertTrue(len(error_captured) > 0)
        self.assertTrue(len(finished_flag) > 0)


if __name__ == "__main__":
    unittest.main()
