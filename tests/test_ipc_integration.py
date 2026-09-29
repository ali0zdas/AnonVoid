"""AnonVoid - Faz 1 IPC Uçtan Uca Entegrasyon Testi.

Daemon ve DaemonClient arasındaki gerçek soket iletişimini, JSON serileştirmesini,
zaman aşımı ve hata mekanizmalarını doğrular.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest

# Adli iz bırakmayı önlemek için Python bytecode üretimini kesinlikle engelle
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.daemon import RootDaemon
from core.daemon_client import (
    DaemonClient,
    DaemonConnectionError,
    DaemonResponseError,
)

import socket

HAS_AF_UNIX = hasattr(socket, "AF_UNIX")


@unittest.skipUnless(HAS_AF_UNIX, "Bu platformda AF_UNIX soket desteği bulunmuyor.")
class TestIPCIntegration(unittest.TestCase):
    """Daemon ve DaemonClient tam entegrasyon testleri."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.sock_path = os.path.join(self.tmpdir.name, "test_daemon.sock")
        self.daemon = RootDaemon(socket_path=self.sock_path)
        self.daemon_thread = threading.Thread(target=self.daemon.start, daemon=True)
        self.daemon_thread.start()

        # Daemon'ın soketi açmasını bekle
        start_wait = time.time()
        while not os.path.exists(self.sock_path) and time.time() - start_wait < 3.0:
            time.sleep(0.05)

        self.client = DaemonClient(socket_path=self.sock_path)

    def tearDown(self):
        self.daemon.stop()
        self.daemon_thread.join(timeout=2.0)
        self.tmpdir.cleanup()

    def test_ping_pong(self):
        """İstemcinin daemon'a ping atıp pong yanıtı aldığını doğrular."""
        self.assertTrue(self.client.is_daemon_alive(timeout=2.0))
        resp = self.client.ping()
        self.assertEqual(resp["status"], "ok")
        self.assertEqual(resp["data"]["message"], "pong")

    def test_get_status(self):
        """Daemon durum raporunun doğru alındığını test eder."""
        resp = self.client.get_status()
        self.assertEqual(resp["status"], "ok")
        self.assertIn("uptime_sec", resp["data"])
        self.assertFalse(resp["data"]["network_shield_active"])

    def test_connect_and_disconnect(self):
        """Ağ kalkanı açma ve kapama komut akışını test eder."""
        net_cfg = {"tor_enabled": True, "tor_socks_port": 9050}
        resp = self.client.connect_network(net_cfg)
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["connected"])

        # Durumu sorgula
        status = self.client.get_status()
        self.assertTrue(status["data"]["network_shield_active"])

        # Kapat
        disc = self.client.disconnect_network()
        self.assertEqual(disc["status"], "ok")
        self.assertFalse(disc["data"]["connected"])

    def test_circuit_renewal(self):
        """Tor devre yenileme isteğini test eder."""
        resp = self.client.new_tor_circuit()
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["renewed"])

    def test_clean_forensics(self):
        """Adli temizlik komutunun iletilmesini test eder."""
        targets = {"clean_shell_history": True, "clean_trash": True}
        resp = self.client.clean_forensics(targets)
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["started"])

    def test_emergency_panic(self):
        """Acil durum panik komutunu test eder."""
        resp = self.client.emergency_panic()
        self.assertEqual(resp["status"], "ok")
        self.assertTrue(resp["data"]["nuked"])

    def test_invalid_command_raises_error(self):
        """İzin verilmeyen bir komut yollandığında DaemonResponseError fırlatılmasını test eder."""
        with self.assertRaises(DaemonResponseError):
            self.client.send_request("forbidden_shell_cmd")


if __name__ == "__main__":
    unittest.main()
